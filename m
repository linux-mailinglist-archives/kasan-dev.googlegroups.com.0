Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBI6DX2IAMGQE7ULTTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D593F4BBA32
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 14:39:47 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id p9-20020adf9589000000b001e333885ac1sf3572652wrp.10
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 05:39:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645191587; cv=pass;
        d=google.com; s=arc-20160816;
        b=QUwq2feRidzmP/b9+LF1xf5JCiTvmPwyeVBU+xtDws6sjW6+eM5e46YwFxdeK5IwXH
         n1Ua8v6TXKA6bSkrpVVSh8PtLi2y/ft6Qubd/YtRiqcKFjeaNpq4rs4sbwdCKXqDmcdO
         TER13BJr9/2uRuDt4CUWIZbcKmYE2e+whHDZp7cJHJK92DmWm+hNX+R/LeKAe9fo5PPD
         8p2Fh/kee+PV0xWjCbUQq3yio+CBm72XIEXJB5fTiZfZmRdkR52TwhAELDPd5IDHjvEF
         Q2kjTcRTI+40xvWnqJHNAytjxnhh9ahaWHmb5AbQX+xDBtbSlr9c9a0ETdYBVYjqdCMj
         9XBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=uso2PpVIVOOLjQqMEaEDEqp+uOhg0fYIHHR73bc3hn4=;
        b=g3tetQ9brqS2ScKoufIBFrKsx290Iaps26r5VDQdwOKtgsDFDJWAuToXJFeyYj7YXl
         MukWg4Fns+Wy+oixxot2Exy4crpHsNrJWCD5iXoppcnudMUSmr7dQ63yRDDmXdGZS5X6
         vyEYgZVW/lxwujGMi3EdLvWcb1MGmLsG1aXyPra5bef4JO/0B8BGxFPckIBsZkJeOnsA
         AWPMJrOAXfdyIeWhkzZCSLwRHdKyRANn3Rot01BLlL7q8fGfW3r/uotkl4XQxZ567/cQ
         lxZIkdYERrowSLXIIH7AkHbAsS2xK+r+dn+95//nvRr0vuv3T3DxKR+qqeNYxzBylhSt
         xZhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=MtHHO6vU;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uso2PpVIVOOLjQqMEaEDEqp+uOhg0fYIHHR73bc3hn4=;
        b=SM/GMrWkIcbI0VL2uRPHggAYiNZOOGryHExeh8i6EpJwJueH31/ctbGBkbAmisqPVx
         DLDhzT/aWImGnfITsgF6VZL2/7R3neG1wJKXlkmfm8lNkVkIlHTut3MZMXLTbRzpHs7m
         fhKho3EYfiXqoudgKwEZm9QsEMffR1Nj9hEcscGZ5k7b8RarYqQfGuIDPjfLskA8DgTm
         +Aayrw2zaUTvqxSYFVvSHQ3PUYrWIvQ0vRuiWrsI/9raAeSsSlbCx3h6VVXGmngT71Q3
         fmtrpnk9UP+RMdgVw8FFHDIGjj1oteu+8Vpxcab0gTUwcr0Z/oBNvKJvY5yaUl9ePwZg
         WySg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uso2PpVIVOOLjQqMEaEDEqp+uOhg0fYIHHR73bc3hn4=;
        b=7z/bvI9Jyg9nneRxy0eMmL8y0DQ5q1yWmw4slIamwnTJvgl6A5wcUGTSDJqYax5RRh
         a1p9w2HP2rOfAH851oii1Ndw5nf73P7X5/pHPsrKEesIo9ZsBvQhx0LuyHv8v8Cqd5Dx
         24T+dVWzzltQSOSsHpfSerxG+8RYry+X5ZnORy4nnVmZa1bg/jb4zE0JupJVlq4mzHZE
         5q3oaH0au63EHz+OHdoJ9Rc21ulbTcoOxkCSj03gG251tfL5RsqcgbLGy51duVkIjVve
         v8/mBs3ONkCbZNqqWlw/Mgtr7niv6u1UE304nhbTyXQz+hldEJpQiBKsxOkJzyEOq7eh
         H9+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MdF6VBWBiHtgZI1B1wrpxz0FbaQ8A3lcpvDUZmQZll1sVP/Wp
	K51/osxEfDkOaSk8Z8VDFac=
X-Google-Smtp-Source: ABdhPJz2CzfNXKQFmQ1o1/7Z9iieV9demaXlER4A9L2VB4sYcwo2MTruGN6ztUroUnQAMyO8u+15PQ==
X-Received: by 2002:a05:600c:1d27:b0:37c:74bb:2b4d with SMTP id l39-20020a05600c1d2700b0037c74bb2b4dmr10701344wms.82.1645191587633;
        Fri, 18 Feb 2022 05:39:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e12:b0:1e4:b617:bc85 with SMTP id
 bj18-20020a0560001e1200b001e4b617bc85ls331589wrb.0.gmail; Fri, 18 Feb 2022
 05:39:46 -0800 (PST)
X-Received: by 2002:a5d:6da3:0:b0:1e3:2f74:f025 with SMTP id u3-20020a5d6da3000000b001e32f74f025mr6197810wrs.59.1645191586786;
        Fri, 18 Feb 2022 05:39:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645191586; cv=none;
        d=google.com; s=arc-20160816;
        b=HWYuYbSXBjnP5ZMzG3kbUzljs8l//5ao8niwdLjREqvtrhhrRFokQOJtJfC49ycWMV
         IRNtZbfVBVm4OhkiVYiZttDtt2UzoTY/MawuZStOZG/lFq3OZw+C5iEhMabSuarKA8af
         hhC213uVXH6sQCcO0115QlC6gEOhMJTNNotLlYECwyMC+GfESBl8fU5H82MCBCS26ACu
         /dt9Sk61v0wZ2Yiw4hL42u4qr5/aIXUKtfxzKxsFA0Meo2FAZofgL6FYa6XCErqRe7ox
         Lbz4aU39yL9kQ/LBVBDfmY2XViGLuHB/VPdHNw/UkTrUf0lzQggBRiY04UYC4k61KIje
         3d9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=JOP3F1szvziyyHwwb25WbMBDR7/phOdbs80dtO/BlA0=;
        b=fSC/5CwsLsMNyI4J7g5DHRLhec3vhM51be2vLUkW2OuR06UjKi31i9NE2Pcew/jCD9
         DDUtusTe2x0v9lw8PvTdj78fqGeNGtueDHIW0TcmbaDxThOsla8QB6Nbimp0QOHDnlI7
         zOq7TRXgmQq5MtH3OmYzGfaizglDKpXUoYQt8muk8Zqo5umwSb4BSl5hthbmxhyBC+Mf
         0qhTDexHTo35aswBLi2G/KCq/zp4aHZj0nzNkDKWwPlx0ECp0M13oNE2kGZHfnovp+kU
         nCGpz8xQ9Ftmf/YE4Jo/cL8VFjGRp43PxO1TeG0ZVS3mRoYDfm6PvExZ/ZgaWFCiQCAt
         VAbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=MtHHO6vU;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id j13si1416796wrp.6.2022.02.18.05.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:39:46 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com [209.85.128.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 77F4D3F32C
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 13:39:45 +0000 (UTC)
Received: by mail-wm1-f70.google.com with SMTP id v130-20020a1cac88000000b0037e3d70e7e1so3181920wme.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 05:39:45 -0800 (PST)
X-Received: by 2002:adf:e5d0:0:b0:1da:4dfb:497e with SMTP id a16-20020adfe5d0000000b001da4dfb497emr6489387wrn.282.1645191585232;
        Fri, 18 Feb 2022 05:39:45 -0800 (PST)
X-Received: by 2002:adf:e5d0:0:b0:1da:4dfb:497e with SMTP id a16-20020adfe5d0000000b001da4dfb497emr6489383wrn.282.1645191585101;
        Fri, 18 Feb 2022 05:39:45 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id x11sm4183619wmi.37.2022.02.18.05.39.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:39:44 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes 4/4] riscv: Fix config KASAN && DEBUG_VIRTUAL
Date: Fri, 18 Feb 2022 14:35:13 +0100
Message-Id: <20220218133513.1762929-5-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
References: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=MtHHO6vU;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

__virt_to_phys function is called very early in the boot process (ie
kasan_early_init) so it should not be instrumented by KASAN otherwise it
bugs.

Fix this by declaring phys_addr.c as non-kasan instrumentable.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/Makefile | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
index 7ebaef10ea1b..ac7a25298a04 100644
--- a/arch/riscv/mm/Makefile
+++ b/arch/riscv/mm/Makefile
@@ -24,6 +24,9 @@ obj-$(CONFIG_KASAN)   += kasan_init.o
 ifdef CONFIG_KASAN
 KASAN_SANITIZE_kasan_init.o := n
 KASAN_SANITIZE_init.o := n
+ifdef CONFIG_DEBUG_VIRTUAL
+KASAN_SANITIZE_physaddr.o := n
+endif
 endif
 
 obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220218133513.1762929-5-alexandre.ghiti%40canonical.com.
