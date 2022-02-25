Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBE464OIAMGQE5JNIGUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A11794C44C8
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 13:44:03 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 20-20020a05651c009400b002462f08f8d2sf2346352ljq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:44:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645793043; cv=pass;
        d=google.com; s=arc-20160816;
        b=ihG4SNhY6pC/mltskbdf5tEx5a62RDvJoBSkiG+rLbMrDKvR5lQ61HtnPqOSW5GzPO
         urCZ+SFfKvZjrLNXoP+zUh1E8wn9XVmBcx8zfRsmp0EEyEywHHocL/hPRJIZJoJacSC3
         6G+5lfvyyJxNB3ptYFZPyVLi0xWcfCtDEfbvU+2j74i5UlcGhKgQHMC6bM15ZZwylMFr
         BY4e3ykoewzD9eoIlAbSj1e8cyDKAVO569sT1kUJK67h92PHCjuw7dOC706ViJwKZBl8
         rGiasyVrGkEgOeFATzj6l9Qzi5kZEwZZi7ITOQqCGFmplSZYF5qjXDvlB0WdVzcmbNS6
         RrIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=EAVbF4GUxztCzeqGR/ceGQvITSqJajDLW3k/7hT8D7M=;
        b=ehJqrkuqAvkRGLDx3Gp0BsYTKNuL76D8jyo4v+04qVsdyG77SEPytqkz14eZgiOEU3
         Rlh7tMj5rheBJwStkGyceFy5bhxz+1IOiiMIdDR02LcjRobkmQ2S+3ULFysG1hYc+Cz5
         e+rOFFKoy9cqr2KDNofLbsdDJxXxEBYr6HnszUm4PQKnVnljHBbi1j8EZTE96UAjR4F7
         xbF/9im75gPH7MWGXk+vI3pbT6jKRPZ6ppq1PNeENtmL1mcejUszO5M+2s8cmx3NNu6Z
         JE3TdyzflEKc9eIgQ7w6oqpKCOewxTYXFsMkBitD99qtPjqGeFoogeiPcV35uUWJUTXu
         OCGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=LLJ6IWhp;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EAVbF4GUxztCzeqGR/ceGQvITSqJajDLW3k/7hT8D7M=;
        b=c3jC4samRk+jUTD5k6qpwAWnbmtDNJPGPfDfofwPDxEPV16hHpwf5uB6Wamc3tvIl0
         T/vZoP2e4+iXjdpnNckqTP9xApA4xM9dfwnLb4iOT4ljl51e4PTyEPp6WOxA9a544Zu1
         EaylLdq1lxPU1HvjDIv4KogPx1ePEF1B2ePWaVQc6putiexSymTr9b6CgIJA3Wx6DsyT
         5LrXBGZK8q5GQ9R8f00CWt5LbdMG/rlGH+HSJfQC9mqvzkLQODEpkaASyUWc1Plb6A/x
         Ua+2/57zapB96i8C0ngf6WJ6Cp8vpZOTHhDyGwdG0Y0oJatsGcuRGcH0jkMy7T9AUwrC
         023g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EAVbF4GUxztCzeqGR/ceGQvITSqJajDLW3k/7hT8D7M=;
        b=VhfcmYLXBQ18Ovaiwslgaszyg0uB0qJcBaXz+N4SG7iBo3wGOkao2dqfLTJHWgE7U9
         MkKzt674Abyj5jYYxezKu/byoYNqWCfTVaXlJm4bafe87UUOJTf10tZZ6dQl8rpenU+t
         cKaNC1CoMWFr45eD+xb+TqdcytPtZ1HXIkgKouEFb2W0hP38/QdjdYAIEkDImFPWwG09
         mtZkS5eDvaPZxy44BPY89YhcolDYvthq8Zxdr6dd9P8yCTV2+EEvbUVfMIzkPubJO00m
         klTvSUNzOf9URpRH/cWi9wRODTC/6cIq1W09MhC1YCttyjsqLmHZ/5xXXAFIxrDBR9lR
         sXeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306OQQbLRkZnq2I4+oO4lhr6arrjTeLq2tFAM3rGxtJ0Pr9y1nx
	l5eTay9r+xm2viuiLtPOcbM=
X-Google-Smtp-Source: ABdhPJyKosKVQbI27XvG0tZcHupFBuWtDh4rY5xvZhaBR35uep+Nrwyv39/s0yerPe5r19sqjt2A3A==
X-Received: by 2002:a05:651c:1725:b0:244:bbe7:2433 with SMTP id be37-20020a05651c172500b00244bbe72433mr5101560ljb.144.1645793043220;
        Fri, 25 Feb 2022 04:44:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8e:b0:443:9610:6a0c with SMTP id
 g14-20020a0565123b8e00b0044396106a0cls2394314lfv.1.gmail; Fri, 25 Feb 2022
 04:44:02 -0800 (PST)
X-Received: by 2002:a05:6512:3d8b:b0:442:628c:73f3 with SMTP id k11-20020a0565123d8b00b00442628c73f3mr4919370lfv.419.1645793042180;
        Fri, 25 Feb 2022 04:44:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645793042; cv=none;
        d=google.com; s=arc-20160816;
        b=ug22BBsCILQR7ZZlG2q+Ph3iDeE7gRzRWvC0Sm72msZVrBbguxnypXZXk9Ra+wXdno
         Zm5UGkNOHxAfAX95WdrVnFx0oUv4KI+76EBwn2Fc8BqgXCJ4CRfrWos7R6ZddaLPLYaH
         xGaeXyVQbX9IU3O8WAGb7DHK9q3ioDd1Yv2BbEGKr48moN8choDPqZMsqXkjqqYz7tD6
         9RdXilGUEA/oPfNwRmW9JV1kNC0aERK2njUSCJuObL/ZNy9jUMcDK/OyJqzqWlxCa6FD
         a/mvDjl1A4jW9V105xEqanhTQ09tA7eQSRtyAr/0jjgu3pnqCFwH6qtcXehO9UFzAfN5
         OK6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=JOP3F1szvziyyHwwb25WbMBDR7/phOdbs80dtO/BlA0=;
        b=BE2hX3Mh7LIkTvZr6/Pic+AmM5dSMitfYKMNHBFP+WY8dTyzGg1f9x7oIZ8QNLsm9D
         udTuw9Bax+X41nfrXy9pUJd7rQKFf9cgByPE2NpMeZ8XV4UVq5QDfH/w6goHsPKhMivn
         9hjTy5RTarvfqx0x6fqD8R1C3nhe45vta+0WYVhm2rnnDQHGxmRYLRu+jj+k9C2JnOuf
         eX+LODp7loxgG/tOBc/YAjnDvCbtXU5GhCoiOpiGwBvePwnNFxZdCc52lAPYxZL44Aac
         Am15WtX60p1xzBbA+kyrbbzfAr3eFGGWjNDnuFknOPzR6PRVPJfJl30cq0kPBsFQC9D1
         YF7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=LLJ6IWhp;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id m1-20020a056512114100b004433d120accsi114676lfg.9.2022.02.25.04.44.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:44:02 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 8C1583FCAC
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 12:44:01 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id i20-20020a05600c051400b00380d5eb51a7so1276031wmc.3
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 04:44:01 -0800 (PST)
X-Received: by 2002:a7b:ce84:0:b0:37c:52fe:a3ff with SMTP id q4-20020a7bce84000000b0037c52fea3ffmr2567644wmj.48.1645793041011;
        Fri, 25 Feb 2022 04:44:01 -0800 (PST)
X-Received: by 2002:a7b:ce84:0:b0:37c:52fe:a3ff with SMTP id q4-20020a7bce84000000b0037c52fea3ffmr2567618wmj.48.1645793040749;
        Fri, 25 Feb 2022 04:44:00 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id f10-20020a05600c154a00b0037bbbc15ca7sm10658533wmg.36.2022.02.25.04.44.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:44:00 -0800 (PST)
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
Subject: [PATCH -fixes v3 4/6] riscv: Fix config KASAN && DEBUG_VIRTUAL
Date: Fri, 25 Feb 2022 13:39:51 +0100
Message-Id: <20220225123953.3251327-5-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=LLJ6IWhp;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220225123953.3251327-5-alexandre.ghiti%40canonical.com.
