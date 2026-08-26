package jnic;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import jnic.match.MatchRule;

/** Parsed configuration file. Schema mirrors the documented JNIC XML format. */
public final class Config {

    public static final class Options {
        public boolean stringObf;
        public boolean flowObf;
        public boolean fastCompile;
        public boolean useIntrinsics;
    }

    public final List<Target> targets;
    public final Options options;
    /** Internal names of runtime-retention annotations used for selection, or null. */
    public final String includeAnnotation;
    public final String excludeAnnotation;
    public final List<MatchRule> include;
    public final List<MatchRule> exclude;

    private Config(List<Target> targets, Options options,
                   String includeAnnotation, String excludeAnnotation,
                   List<MatchRule> include, List<MatchRule> exclude) {
        this.targets = targets;
        this.options = options;
        this.includeAnnotation = includeAnnotation;
        this.excludeAnnotation = excludeAnnotation;
        this.include = include;
        this.exclude = exclude;
    }

    public static Config parse(Path path) {
        try (InputStream in = Files.newInputStream(path)) {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(false);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            Element root = dbf.newDocumentBuilder().parse(in).getDocumentElement();
            if (!root.getTagName().equals("jnic"))
                throw new ObfuscationException("config root element must be <jnic>, got <" + root.getTagName() + ">");

            List<Target> targets = new ArrayList<>();
            Options options = new Options();
            Set<String> seenOptions = new HashSet<>(Set.of("stringObf", "flowObf", "fastCompile", "useIntrinsics"));
            String includeAnn = null, excludeAnn = null;
            List<MatchRule> include = new ArrayList<>();
            List<MatchRule> exclude = new ArrayList<>();

            NodeList children = root.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node n = children.item(i);
                if (!(n instanceof Element el)) continue;
                switch (el.getTagName()) {
                    case "targets" -> {
                        for (Element t : childElements(el)) {
                            if (!t.getTagName().equals("target"))
                                throw new ObfuscationException("unexpected <" + t.getTagName() + "> inside <targets>");
                            targets.add(parseTarget(t.getTextContent().trim()));
                        }
                    }
                    case "options" -> {
                        for (Element o : childElements(el)) {
                            if (!seenOptions.contains(o.getTagName()))
                                throw new ObfuscationException("unknown option <" + o.getTagName()
                                    + ">; valid options: " + seenOptions);
                            setOption(options, o.getTagName(), o.getTextContent().trim());
                        }
                    }
                    case "includeAnnotation" -> includeAnn = internalName(el.getTextContent().trim(), "includeAnnotation");
                    case "excludeAnnotation" -> excludeAnn = internalName(el.getTextContent().trim(), "excludeAnnotation");
                    case "include" -> parseMatches(el, include);
                    case "exclude" -> parseMatches(el, exclude);
                    default -> throw new ObfuscationException("unexpected config element <" + el.getTagName() + ">");
                }
            }

            if (targets.isEmpty())
                throw new ObfuscationException("config must declare at least one <target>");

            return new Config(List.copyOf(targets), options, includeAnn, excludeAnn,
                List.copyOf(include), List.copyOf(exclude));
        } catch (ObfuscationException | IllegalArgumentException e) {
            throw e instanceof ObfuscationException oe ? oe
                : new ObfuscationException("bad config " + path + ": " + e.getMessage(), e.getCause());
        } catch (Exception e) {
            throw new ObfuscationException("failed to read config " + path + ": " + e.getMessage(), e);
        }
    }

    private static Target parseTarget(String s) {
        if (s.isEmpty()) throw new ObfuscationException("empty <target> value");
        try {
            return Target.valueOf(s.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            StringBuilder valid = new StringBuilder();
            for (Target t : Target.values()) valid.append(t.name()).append(", ");
            throw new ObfuscationException("unknown target '" + s + "'; valid targets: "
                + valid.substring(0, valid.length() - 2));
        }
    }

    private static void setOption(Options o, String name, String value) {
        boolean v;
        if (value.equalsIgnoreCase("true")) v = true;
        else if (value.equalsIgnoreCase("false")) v = false;
        else throw new ObfuscationException("option <" + name + "> must be true or false, got '" + value + "'");
        switch (name) {
            case "stringObf" -> o.stringObf = v;
            case "flowObf" -> o.flowObf = v;
            case "fastCompile" -> o.fastCompile = v;
            case "useIntrinsics" -> o.useIntrinsics = v;
            default -> throw new IllegalStateException(name);
        }
    }

    /** Accepts either binary (a/b/C) or source (a.b.C) annotation names. */
    private static String internalName(String s, String what) {
        if (s.isEmpty()) throw new ObfuscationException("<" + what + "> must not be empty");
        return s.replace('.', '/');
    }

    private static void parseMatches(Element parent, List<MatchRule> out) {
        for (Element m : childElements(parent)) {
            if (!m.getTagName().equals("match"))
                throw new ObfuscationException("unexpected <" + m.getTagName() + "> inside <"
                    + parent.getTagName() + ">");
            out.add(new MatchRule(attr(m, "className"), attr(m, "methodName"), attr(m, "methodDesc")));
        }
    }

    private static String attr(Element el, String name) {
        String v = el.getAttribute(name);
        return v.isEmpty() ? null : v;
    }

    private static List<Element> childElements(Element el) {
        List<Element> out = new ArrayList<>();
        NodeList list = el.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            Node n = list.item(i);
            if (n instanceof Element e) out.add(e);
        }
        return out;
    }
}
