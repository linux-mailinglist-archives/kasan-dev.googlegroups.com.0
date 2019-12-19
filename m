Return-Path: <kasan-dev+bncBDQ27FVWWUFRBHUM5PXQKGQEBWZ5YCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EEDF125895
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 01:36:48 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id m18sf1461508otp.20
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 16:36:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576715806; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gie8cQDSIuR3yWftoUV4Q+nljB9IiQBEDFanJi9JmD6nGKdBZ4u/FkTPnlpBpKAnAz
         tn1BxeDLtU5G3liZfvp7EjHQhqGfpSaDUxT0AZ0vh+hgRpVaNkfB8rUOtGHHzkz3O9FR
         R+btg8syyqltHgghlmZDVXGmi6uEWgbmvUd3VeLuL9Z45DPbsBTj8Asr2utXCyHo52Tx
         l0FPuQFZ0kenZFCaohl3GI1h5QjxKSH6/61k7sNqzrmwR2K0SFM+J00jGNWg0FXn3ct1
         +wTcvuytc4k058xZxMnFfM8kRAqJWMKyEg0Or/U51CxXZt1KCERI2NtukczSJbI3Rj1W
         cBzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YZTvIPgj/Ui8SoUU1D6EGzjZi0Rdc4aiEAPE3zL7IJ4=;
        b=acBXRa2r38XiDhAeVJRryMgEllCz9bpa2j8/cQgNtNrNOydKcfeoN+aULG1EGA9D6C
         bOzLtgirvNBYo5y4ulkiBsceaKdPKbtgCF4lLmLPkIhRn0Cf13p3UWRiuaOWve/XaHD9
         L+DVriyDVjml8+HHfNodhrL6V4mtKxYLzj9zv3yt4FigRCI8BlD2h3oNTtOFUIvgxAGc
         ssAaljwSe06B4rLGuWAcWzCCXSJb5empiWTUTtrsbTci9R3ZtXvOxoyFQf9iuZLXfSV3
         +YbfiyRcCCHu8WyQ2eAb5UqqZPm6OO4bLiJFlWGN72NUMlImlZza4yBvUguSHDz6zjPv
         eOiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CuenhOgJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YZTvIPgj/Ui8SoUU1D6EGzjZi0Rdc4aiEAPE3zL7IJ4=;
        b=NV65AtQKqT6bjUsSK7D8OHWLpSbmtE0cY6DibLUCtOQt7ro1GVqK9Zgfk0kUuCV5LP
         uSerEwM6AkTCdukbZvb/f89RHByHqYpSucjvGLbm+iUlEjE92E5EtqpneJPfuZN5dHaX
         MrRUENwkzNxTgRG5J3vtJsw8ZfUa0Y71HkP1ViFXZhBCRfN7LeqQHa8uOPvKvds/y2cG
         xxK9fltsupU47KSUJLMBwvmHUEqEd8URz08HCm48qcbeQtZZ9oM72c2zJ1bbrnVyZqsD
         WEyufnewEaLx7ZfBQpFko8GDJSLTPdJHFffFFSeqLYSQbf8d1BXrWu9qSbofhSjranYU
         aYHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YZTvIPgj/Ui8SoUU1D6EGzjZi0Rdc4aiEAPE3zL7IJ4=;
        b=m1xWzCg2/LCcVOxn1pXy057a9qHw54HPC4hQFcaszidqciqSk9rei4Jq3xWfve7yAH
         2IAYpLceclAv1rpF0tuMXbOix90jL8aQZ+jeEh3ECWq0TK1uuVMLdi78bXj57f5/lmQY
         3Hww4b6XetggsPTSfkH3Qq9ZOFQqpL9RZlofw8LjnsGcUx7J6x2symnJRXY/JtAKd5Gp
         0iUf/BGr6ipPTEi5p2eQW8GU155n2NDU6bfaoo/mqcd4cbpZJvgRM7S5R5d4tcnYbg9O
         RYHobSqdMw1NiahoOtw2SgDtxwy/0/17cUsEQfGCGz1iQYzJZZimpM+ULZqz+z10Zx1f
         W/ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUeYpIwkJeMqgn2Kpl8EGUC9Qrg+tDaRiNAnJ60bsOsuVrJuRnp
	6EMiMTdNp7SqkEEOFeR/kc0=
X-Google-Smtp-Source: APXvYqwHRp5Xg73SKxu0DGxwSA68/971L2D529H29ksSXtcmMmJoLQTAWAb9dfOGRj87rwxBHpkuSw==
X-Received: by 2002:a9d:6196:: with SMTP id g22mr5904397otk.204.1576715806522;
        Wed, 18 Dec 2019 16:36:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c694:: with SMTP id w142ls297692oif.6.gmail; Wed, 18 Dec
 2019 16:36:46 -0800 (PST)
X-Received: by 2002:aca:df07:: with SMTP id w7mr1743722oig.145.1576715806072;
        Wed, 18 Dec 2019 16:36:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576715806; cv=none;
        d=google.com; s=arc-20160816;
        b=DEs1wCP6kjH0E0xDxoik9slSz2L+YbS9DA/TeDj92Xnb502on10KWqD7AdQqZ2AAdY
         0PVCTg8oLg87JHh+QtNmAAeq1bQKeeQn6gHwSiyc+jj8oIJOhQ6wtPFw/N5mzr5e/iIq
         HkigXvg9tP6o+7kTK4A38BwkuBGUXLHoBlQ9+YBwa/X8e/pEE8DOHxNT5c8izrYgtsg0
         Wh40QdaSHdmmYxJO2Wus5Di+Xes2lIFAM9luezn5kSTfSvxOhEvtREn8e9thdhu5HfSb
         qkI0dG+BrSOwVgMHtgHV2o1XIK+UaXK2WVavUfsG+tUoAGbFTm2uaCLxzoxM7W1FgSKQ
         74aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2sxbAlXpABK/W64yfjeUTt7MDV8jfwT8E3maFR+CaL8=;
        b=q5GULUlHNOvSiJF1f6P6tpbFBl4j8c+V8YZiJmKkvoKTncUfdVcHaxcAaMWaoAqcmE
         xixY+t1T8xXtXf2C1yy2S+h2t2lYOI++VcBJjaC/jUOaw7/DhAGfKe3sBkZ7NMro+Sts
         ay6XN6jQbai9W8rJdwz6b5J/quAvLcxeHKOyF2gWEXOTsdM2+PpllQjY9jl5ttZGWw8X
         3e3ktZhWS8bQBDme2b2G4JqsKXOJwre9M0WsE06m5WkqjnBSLa5YdqXdg2aB3hJmFx6P
         hUHEjM7YCBEXboKYFG0NXFzNQCSgvcO5Hqs8xH+YrbX87eW8CKawQB+Zd+Qg91ua7uox
         r3dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CuenhOgJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id a12si53105otq.5.2019.12.18.16.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 16:36:46 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x185so2163284pfc.5
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 16:36:46 -0800 (PST)
X-Received: by 2002:a63:1447:: with SMTP id 7mr6070116pgu.22.1576715805301;
        Wed, 18 Dec 2019 16:36:45 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b05d-cbfe-b2ee-de17.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b05d:cbfe:b2ee:de17])
        by smtp.gmail.com with ESMTPSA id e16sm4799301pff.181.2019.12.18.16.36.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Dec 2019 16:36:44 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 2/4] kasan: Document support on 32-bit powerpc
Date: Thu, 19 Dec 2019 11:36:28 +1100
Message-Id: <20191219003630.31288-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191219003630.31288-1-dja@axtens.net>
References: <20191219003630.31288-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=CuenhOgJ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

KASAN is supported on 32-bit powerpc and the docs should reflect this.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst |  3 ++-
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 14 insertions(+), 1 deletion(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e4d66e7c50de..4af2b5d2c9b4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+architectures. It is also supported on 32-bit powerpc kernels. Tag-based KASAN
+is supported only on arm64.
 
 Usage
 -----
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..a85ce2ff8244
--- /dev/null
+++ b/Documentation/powerpc/kasan.txt
@@ -0,0 +1,12 @@
+KASAN is supported on powerpc on 32-bit only.
+
+32 bit support
+==============
+
+KASAN is supported on both hash and nohash MMUs on 32-bit.
+
+The shadow area sits at the top of the kernel virtual memory space above the
+fixmap area and occupies one eighth of the total kernel virtual memory space.
+
+Instrumentation of the vmalloc area is not currently supported, but modules
+are.
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191219003630.31288-3-dja%40axtens.net.
