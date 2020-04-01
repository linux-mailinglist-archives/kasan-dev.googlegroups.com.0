Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP6USH2AKGQE3QNFAMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A9B319A94D
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 12:17:37 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id w3sf20575601qtc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 03:17:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585736256; cv=pass;
        d=google.com; s=arc-20160816;
        b=CvB4RmrqLJC+EP7ijIa3PSazYgm7U7YttLTMdJDsVZ06epNHKp+wryV3nYXrifcYVt
         FLlRRiUIc6ohlq39g/I515xJF/c8uE8hkPj+lX8jsu80raWD/2hp4L6vCAWUSw2q9I4E
         SEJ88818jnznRiiWjrTkU+SJL0CeOgoeANTLj8XgmhL/sfinaSAcVeszwpZqGNaUM1S2
         72uSh7DCntJj+7OwSmZ9eb2tt6aCXAzqGWY6eymVrn25+VURJWkhHWE81FfQatfaGQQe
         8DjzhFEOGsTYr/L59S75OqtFP0KXjOuyDGvgjbOadpPVodJ5y1PGpN5OWdQDHhA+Vpig
         tZYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ictvvsosnL0XYjhJzzH9t3Dfk13WdemFY5YCUI2/cOI=;
        b=T2UzBoejhlO7eSKhyaj5W7dv7WmKyK7FVyqIW+ZwTtl2JvUpj1mVVv3AQksfP6gEBI
         D60IuY80aJpmJERKEyWVJEMMJAOTZw0hY2NwI1BsKomjI38jRve3KPNHhmhhhIEZitAz
         fbW3teoXfIvvJ+UUQu8KCY80lqmnX3dI9bVEZwpaZ1HxqAvB7QoC9XWRQFYESajRhGWS
         YCabBiqv2nYrz/cXn+eKvACWV4SSeEi/loeQbJ2pfN9uEBUbyeYToSjisAD54qT866jA
         zVMrnCmsSHsiV9JoJ7g7FC84wPSBs9Xk6XRQwmg0LpZkeVZTf5DoZG+cw8fiIJteveDQ
         BzKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gucp0oNn;
       spf=pass (google.com: domain of 3p2qexgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3P2qEXgUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ictvvsosnL0XYjhJzzH9t3Dfk13WdemFY5YCUI2/cOI=;
        b=XtXlcTc4CrW9f5WUiM3kj8YlJpFBZ3fBgyKuiJiKz/1zfThuF3wV462Bu3g0Ih6ZRp
         QHESKErL627p7hKbBpXxF9yBdXsDXvysEN6WwbAEb7j3km5m8sWW2Xq/xuk06X2rpajw
         pE/n5plEgCmcb7uXNoImDiJrhYqy8QxbG48x3+6Gmevz2D6C0mk0JWEfIN9tV8tjrLqo
         gU1WA8eKetzvdXzFw1SIqVg16JtsIF7TITGsTwsKTrOhllRwl/tey9Ptg9Qx/qEdXhTi
         eb/Hdh+tNqz1ezM/Vo9WvDSHZN70JqB+i/OvtORJzyPhe5+j0SVbOHp+EnnMycoT/iQL
         V4pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ictvvsosnL0XYjhJzzH9t3Dfk13WdemFY5YCUI2/cOI=;
        b=Do60ah/Z1FOFmQoPp7TgD9jzDf0uaLy4lWh+jUyteLmG8KRDdKg+BGkkEFlZ+A6w0J
         I6eOp2fcjHkbQW9AmIl8kqNa38HA5C2cB4/3nYN7YB/KrVljIhIzNRBN6xk4dx82qLgX
         XSS/wovD9OemFhNED6SgMSLdyw9nEmsWnsdwkRJhh7fLTmR2eM8O9YSN3j1m1/bdOySP
         +XWTa0kyV2seL6dD2jy3wgTUU4710LXgoz8GGNnJDW2UOLJrq64doeLKilu88e+omqkI
         XWmna0brgy4KoJ8RBj6cbx1WqaAL4qstYp5lqchqcJ5Q/qXquWtRoLVLCY3a35AbLRlj
         WysA==
X-Gm-Message-State: ANhLgQ2huvvDDvOzLst/Er+FERG2yuVBXu0WlWzGcOu5i7xFVsPD/EHj
	h/EEwUEQeJqgas/zzdbmGTE=
X-Google-Smtp-Source: ADFU+vtqZJhBKCKMw1KQ01MyypjOmUcrB6VJLb4pDlCnBlHxDaDpMbYwJX18pVg4rmhYe8rXlIy0FA==
X-Received: by 2002:ad4:4964:: with SMTP id p4mr20895319qvy.220.1585736256036;
        Wed, 01 Apr 2020 03:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2521:: with SMTP id v30ls9697275qtc.6.gmail; Wed, 01 Apr
 2020 03:17:35 -0700 (PDT)
X-Received: by 2002:ac8:d8e:: with SMTP id s14mr9490150qti.204.1585736255614;
        Wed, 01 Apr 2020 03:17:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585736255; cv=none;
        d=google.com; s=arc-20160816;
        b=rEph+95SDVlQ0xbdGVVMxY15WAuBeEEa9Xq5k9yM2NthkACwpnwnac64vUXvW/UAn4
         C1ZR58Mb6kTj30tYTWOVkRrOY71IVYU8Z1PpcQBM+LzsqlcP8uMAA+M47nbzTCVIzmsk
         8u9u/TMOGcOsB/z0w71Y7b2TJDPK4eM1UoUiXb7UimIfw9rE9JpwuNej/2JD+McN2nSD
         pQg3v3zmLrtjjZDbEDvMc0n5PyLt7rPAMS7qK8G75D2sTWlL3e8CeXAAA7K2PJQa14jQ
         utMhBQgr+bt6R3VNzXOwfQSsMR07JFCCz2RITMsZmcSB/k6mBXYaEoGgSmN+VFl/3Mq3
         ne6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=bqlNdECR01eLEMLPFpBUwIDjw5hjyGCsJb8UrwtQ8N8=;
        b=mphw2ofQ9+Yp/QSWqYLOEiu0aIQyXRPcXAoAMI1qK9QFhIHFKaoE5X+jHZ9i3EMRJP
         eOTGGgDmzdURUn//+AGo6Pla++7poZxhiO6NjJiYb14BLvQVi2m2TsoFMaIQiOSQ9wgK
         8qwSN5nVxOBpNndHTP2rh3TDKNJhnNhfYZ32uZM3onU1Uid+ttn/tPMtiwwdrM1ocq6J
         PHtoheSSN4tq3clBqpXmYeqx6kR2k5WSVOIY66iuz28ErRyQfxKJVDcgWU7spftfjFGi
         el9pKQ4OJdVn17OoI8P5Ah0IuKOIb+1k8zUNkWi/XbA9OIoSLNep1qvzS5Xlw3UElbz6
         HcXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gucp0oNn;
       spf=pass (google.com: domain of 3p2qexgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3P2qEXgUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x94a.google.com (mail-ua1-x94a.google.com. [2607:f8b0:4864:20::94a])
        by gmr-mx.google.com with ESMTPS id z126si88649qkd.2.2020.04.01.03.17.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 03:17:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3p2qexgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) client-ip=2607:f8b0:4864:20::94a;
Received: by mail-ua1-x94a.google.com with SMTP id d2so9959878uak.11
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 03:17:35 -0700 (PDT)
X-Received: by 2002:a67:647:: with SMTP id 68mr14157321vsg.23.1585736255163;
 Wed, 01 Apr 2020 03:17:35 -0700 (PDT)
Date: Wed,  1 Apr 2020 12:17:14 +0200
Message-Id: <20200401101714.44781-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.0.rc2.310.g2932bb562d-goog
Subject: [PATCH] checkpatch: Warn about data_race() without comment
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, apw@canonical.com, joe@perches.com, 
	Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gucp0oNn;       spf=pass
 (google.com: domain of 3p2qexgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3P2qEXgUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Warn about applications of data_race() without a comment, to encourage
documenting the reasoning behind why it was deemed safe.

Suggested-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/checkpatch.pl | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
index a63380c6b0d2..48bb9508e300 100755
--- a/scripts/checkpatch.pl
+++ b/scripts/checkpatch.pl
@@ -5833,6 +5833,14 @@ sub process {
 			}
 		}
 
+# check for data_race without a comment.
+		if ($line =~ /\bdata_race\s*\(/) {
+			if (!ctx_has_comment($first_line, $linenr)) {
+				WARN("DATA_RACE",
+				     "data_race without comment\n" . $herecurr);
+			}
+		}
+
 # check for smp_read_barrier_depends and read_barrier_depends
 		if (!$file && $line =~ /\b(smp_|)read_barrier_depends\s*\(/) {
 			WARN("READ_BARRIER_DEPENDS",
-- 
2.26.0.rc2.310.g2932bb562d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401101714.44781-1-elver%40google.com.
