Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBKWFUSNAMGQEPOAELVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A22395FEAEF
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:47 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id r16-20020a05640251d000b004599cfb8b95sf3273391edd.5
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737387; cv=pass;
        d=google.com; s=arc-20160816;
        b=rp/TZV7lWs0/ZlvX4BH9xuSIVavqpp82rx2Ym4IzL/ylu2awy8mMiKG7HI2WaoYsX8
         ueWs61mkLL1mt8Kw5e5iTF5JIGHFRJukrYGdIf5wXqw1uhFqeFNNLBAviXbDS1DvvppG
         u/VpjnHE6EjabAbxxFGeBZl2NWEIOasGgxepykndOe53zsLYIRsAK7MhSCUAWvEed9yZ
         gkikujlnY3o4Yoxm9EXkX1xhoVkx510AxyDPrTO+UuNyj2ZRz9/rku0Ucg3ytCSTFqNT
         AGLgwCykpMECeZVv9MWC/sb/G+iydqWFETDSW6MptodxEv1DNjyx2X7KSMNThhOchXyE
         WH2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=SV+UeY1qBDrO1wBhAFIXbA0cVLI0FDtjGH0kYnw7Em0=;
        b=HGzK25bpU1WsGDcRdeji606G2qPQmIWZLeDEVjcIPi58j9u/CjBE/ty8KJTOvswWQD
         aMID/XC9Et3FUpxvCo+dgGI+JOmHPfYXYtgFsd48JVG0S0bpyhETSsPlpppmc+EH2LMD
         oOuItQm/XWbKucdBqKd0eMsCEvp1aOny227YekioB4iShYS8YuiE5hyYRdBBUGhKr4Hs
         5QU0TESBvbTjShiIV+hMKCv6xIhjn6YhJNe2rl5kWSfT1N11NJvTvNtsqqkbc50uJe6E
         tIlSDMyxzMbItdmO5RPk8zvgeCRrZKPNMgUJTh9lUMPp7sm735niP43meU+fPFvGNRlF
         QX8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oC6tSxas;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SV+UeY1qBDrO1wBhAFIXbA0cVLI0FDtjGH0kYnw7Em0=;
        b=fur0n2XRqpFOoRwnCRQEwkiOLwxdzn4m25otGGZZRjaxHsTdJf8E2BMEtDd5yGnpXL
         1DOpzPfJ4nHvUKrJfi6vhnrrhIGIoBbnAMmP+gITNQZZIMa8vRW7hS8I4ty3AS9rz1CA
         aqR+Kmy0MxVoDDA5MPlooZiAsLZ37lzFElTauuA8sjZISok5FUjrDcwcrlkyJlAswMo1
         60uwJopb5FHsRHlhsupnCvvrxcMco2NJhMcz4p+mJJ7003T2yP4u1XlTpMNyu1QeIDrw
         3vxynT+mP7QiVtkihDRPQCS0Z9acXsrTD0avCnRDXi2R/up17XARL60RlRmBkVCE1LYK
         JDOQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=SV+UeY1qBDrO1wBhAFIXbA0cVLI0FDtjGH0kYnw7Em0=;
        b=MSzjxkfM1gqwXJh+4lzf+1+IUlL9kLAH5u/zTioE+sNr6rjzZWoO8ngrqOI33OK0C2
         jMkGrnhvI+DCXaJIPrIpyg3f9uT129XXNMXQSSGm6E+B4PAN8Jf/Ia9HwmA2nelbTvyi
         bRgEsaG31AMKNiFJgDcSJAJNvU4R5vGUuk06YUhNkpdCP+mWRiudW24GD5usd236k7Nu
         mxr9gq0b2G+CtFJ3S+nW2lJL8QMAvzpXofaQzLqZDoUrl+lOdG7SE2la3ztVFIgX7mHX
         69H752JmhpMl56O4npeX0gv2N5t1JzPDSSHUFLwovRIgsD9zjqoLE0nRMpCpIS847cBU
         8swQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SV+UeY1qBDrO1wBhAFIXbA0cVLI0FDtjGH0kYnw7Em0=;
        b=FxCyhwTv8IutnfupPRssEcsJF/0KFag5a5Jx21d/qgN2z03PzHbuTBNpJJ3Cw17zw6
         gyfLq1qJOaLHzDlyoKNf0R5E1r5Fj9IhIE0cF7JX5AeNT6P/4nTACbhT+LkGF7ifRxSh
         PNIXpzbQH9QE4KKKN29/MtpufYUpulfFQrMNuGGHAd8TSYdVAVWMn2ahBxknqcusYlfZ
         MpGdlFsAUEXvclCbRB4iL7AYWQGs2Li2FVAKHAhlxaThA+oX0b2z0rHGeo8elOtI/Hgk
         7N8j+UN6CzCxSSwGrvVqGLduXG+41IntdKOAODiafIJUKx6FJHSTnXFcQzYXTXtk0UdG
         IdNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1w8AGuQ73D0zVR08cwfJJuKw3tVh0TjK+59S4dGVp5ondHKOlX
	f3uHMWO5A1hAq5Fmy9J1VuU=
X-Google-Smtp-Source: AMsMyM7jsb+W0Tccf4LhSvyxlmE9pQ/Rz5NlS+FU3lYWmfV2tjofBUMLEys0uxQMZdgS2pgA1j2qnQ==
X-Received: by 2002:a17:906:6791:b0:78d:4051:fcf0 with SMTP id q17-20020a170906679100b0078d4051fcf0mr2689760ejp.591.1665737387098;
        Fri, 14 Oct 2022 01:49:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:86c7:b0:73d:afe3:ffd9 with SMTP id
 j7-20020a17090686c700b0073dafe3ffd9ls2185342ejy.10.-pod-prod-gmail; Fri, 14
 Oct 2022 01:49:46 -0700 (PDT)
X-Received: by 2002:a17:906:5dd8:b0:78d:efa7:f78d with SMTP id p24-20020a1709065dd800b0078defa7f78dmr2783085ejv.641.1665737386000;
        Fri, 14 Oct 2022 01:49:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737385; cv=none;
        d=google.com; s=arc-20160816;
        b=xvpsv+SlWHTLBZaX1CtjD/owlgDR37s98ud8CZSdW50f+ebD9POFLR/Azi7dLBZFzD
         3pMgGf6KfecK1R5IjJODdvUlo1R39SBcyLGjrnb3auDSpgB4ySm1uj4VTyxoacZQJpCW
         hOwGKI7jSQHA4zfxZ70x7/UNWBjpMFe+f9aPtZ6/NBhJFECA6s9ztkABPwQChF44aa33
         EdKt17IS4ICufG0dGmIO8Htq49vlI4QH00ehITBgABsHtVQwudtVeZYvANT/57ujh0fM
         ek8D3/5/yBS8vUHUPGw+B7sa4M/Iv9PdoyTfo32/2XWlLiFJBVvcKVJSlzDU88LWDdOX
         fyYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e7OO4yxaPUsVNNTpu1wi+buwSaoss8IhgddIo1BpRyE=;
        b=MkMH3fkzMih837EqA1FyWaWJu3zP0MyH1Hvt3rXEaOy6SiWga14szeUrnPC/qfNu0y
         FeR1CYwaTp440odHVHBK3BZCrRhoUBwVksbzLXPrbxzGOqK5K1wcXv2aMXrEXa1Ho04N
         Q4ulvd70/9z7JF45V/6QMHFt2NcoiCRYgCoPPWHISbPnkZhv1GJQ3YQwx1Pj7k5jfPSy
         xBhnqENxEDNEqigq/a7H7KGBRK6wrg7vF9PhUzTVX5RxMYSOJY4UCFTC4g/iUd+rUEqI
         52ZXjfm5lIYqQ9x6SNKt53H4jveWxxHJGfIZMSRFdhPiehDRH3XpjDnfKtyzgJTO0QEq
         TJuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oC6tSxas;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id j11-20020aa7c40b000000b0045bcf2bacbasi77669edq.2.2022.10.14.01.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id c3-20020a1c3503000000b003bd21e3dd7aso4910228wma.1
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:45 -0700 (PDT)
X-Received: by 2002:a05:600c:5388:b0:3c5:4c1:a1f6 with SMTP id hg8-20020a05600c538800b003c504c1a1f6mr2698975wmb.11.1665737385463;
        Fri, 14 Oct 2022 01:49:45 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:45 -0700 (PDT)
From: Hrutvik Kanabar <hrkanabar@gmail.com>
To: Hrutvik Kanabar <hrutvik@google.com>
Cc: Marco Elver <elver@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	kasan-dev@googlegroups.com,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Theodore Ts'o <tytso@mit.edu>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	linux-ext4@vger.kernel.org,
	Chris Mason <clm@fb.com>,
	Josef Bacik <josef@toxicpanda.com>,
	David Sterba <dsterba@suse.com>,
	linux-btrfs@vger.kernel.org,
	Jaegeuk Kim <jaegeuk@kernel.org>,
	Chao Yu <chao@kernel.org>,
	linux-f2fs-devel@lists.sourceforge.net,
	"Darrick J . Wong" <djwong@kernel.org>,
	linux-xfs@vger.kernel.org,
	Namjae Jeon <linkinjeon@kernel.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Anton Altaparmakov <anton@tuxera.com>,
	linux-ntfs-dev@lists.sourceforge.net
Subject: [PATCH RFC 1/7] fs: create `DISABLE_FS_CSUM_VERIFICATION` config option
Date: Fri, 14 Oct 2022 08:48:31 +0000
Message-Id: <20221014084837.1787196-2-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oC6tSxas;       spf=pass
 (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Hrutvik Kanabar <hrutvik@google.com>

When implemented and enabled, this should circumvent all redundant
checksum verification in filesystem code. However, setting of checksums
is not affected.

The aim is to aid fuzzing efforts which randomly mutate disk images and
so invalidate checksums.  Checksum verification often rejects these
mutated disk images, hindering fuzzer coverage of deep code paths. By
disabling checksum verification, all mutated images are considered valid
and so exploration of interesting code paths can continue.

This option requires the `DEBUG_KERNEL` option, and is not intended to
be used on production systems.

Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
---
 fs/Kconfig.debug  | 20 ++++++++++++++++++++
 lib/Kconfig.debug |  6 ++++++
 2 files changed, 26 insertions(+)
 create mode 100644 fs/Kconfig.debug

diff --git a/fs/Kconfig.debug b/fs/Kconfig.debug
new file mode 100644
index 000000000000..bc1018e3d580
--- /dev/null
+++ b/fs/Kconfig.debug
@@ -0,0 +1,20 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+config DISABLE_FS_CSUM_VERIFICATION
+	bool "Disable redundant checksum verification for filesystems"
+	depends on DEBUG_KERNEL
+	help
+	  Disable filesystem checksum verification for checksums which can be
+	  trivially recomputed from the on-disk data (i.e. no encryption).
+	  Note that this does not affect setting of checksums.
+
+	  This option is useful for filesystem testing. For example, fuzzing
+	  with randomly mutated disk images can uncover bugs exploitable by
+	  specially-crafted disks. Redundant checksums are orthogonal to these
+	  exploits, as they can be recomputed for crafted disks. However, for
+	  testing it is more reliable to disable checksums within the kernel
+	  than to maintain image generators which faithfully reimplement
+	  per-filesystem checksum recomputation.
+
+	  Say N if you are unsure. Disable this for production systems!
+
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 73178b0e43a4..4689ae527993 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -979,6 +979,12 @@ source "lib/Kconfig.kmsan"
 
 endmenu # "Memory Debugging"
 
+menu "Filesystem Debugging"
+
+source "fs/Kconfig.debug"
+
+endmenu # "Filesystem Debugging"
+
 config DEBUG_SHIRQ
 	bool "Debug shared IRQ handlers"
 	depends on DEBUG_KERNEL
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014084837.1787196-2-hrkanabar%40gmail.com.
