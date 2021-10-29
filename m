Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB5P75WFQMGQE4ZNR6YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1109743F668
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Oct 2021 07:00:38 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id k15-20020a0565123d8f00b003ffb31e2ea9sf3659565lfv.17
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 22:00:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635483637; cv=pass;
        d=google.com; s=arc-20160816;
        b=IqqMYXEkefshN92Y+ebPdKylm0wX1HcTF2WymPH/FrC2tZYm3UAxe7ihlqaP/Em/+B
         fkjgc4jWRVDPVPeScqJPN9Yt4l8D5FipMdc+/acWWRc7w9klOkE2WWnuOloVjJymPvyk
         +s2BeulJsuPrY9TLOn5X/mYz3yTXJPm1QUknS8STs7VC1C6JHP6kPXpVOmqcd4kHjPh/
         fyhUFCO47YAAHGLNFpz4v2CWu9WWD4QOhNSELOJFI3M11ZYz9H6cVXBGVPka50kSwHBt
         7MwcMTiJl9LnX3t1568LtFV4xrWgho8nY8OVdkjlciQrZim0TnFupiMx1rEB62BIyuYn
         bvQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xDXflMGg/2z8rpmfEKz2XLTGBenHxW4qOGAL0nVWlq4=;
        b=ZD+1B270AtDOIF5pAWT+kdg8vEc+GtV8/n+wDd7uK7torM5fJgXBsBruV50Zuqk1AQ
         56e4wOqhXeYN17nMrMXZVhyQDOVqFwZjZPTYk3HWOVPvwSlUqjOijQskWQqH3OwmKduX
         nJS7Eu6RiLGVySm+QdBWjcKwsfMJe8FeYnddDpbRU4tjN9a2XydkrVVDY3Ysdg7D1FaQ
         zTnmPSNhLY9CjRgg9uNtOzedeIoy3FVKgKdSDndNYMfgULMkhm1pyWEULJBUdlViZPCn
         8mwtneVcnZp42qECqbMulGI1tfnO9gRQQMZk1Cd5V0UqF3gNgoCxdAURCu1f6tolgnKi
         3Ldg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=dYEoaswM;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xDXflMGg/2z8rpmfEKz2XLTGBenHxW4qOGAL0nVWlq4=;
        b=R705X468yNNovIMgKJn4rGJrPcAfF5xkUC7i0IsuN8hYWR2JdmDNxy/AEtHKrgitSw
         eO/3eJI1LdNyBHNm1mwKZEK87Hs4jodnaNb//QujXRAXIevVmFz+a0yZ5JXRaBH9YKZj
         W74yO8cR5UATXS0j7HDHvT5UsinSruUiOFYYu8tBJP+K5Ty9Pd3uvfmgY3YBfPCdxcMD
         n62G90zEZu7a0ib3xps4IHTZx8YpRPtXoXBfkQMsoC9dqJPczi/wxw6ZumfdHFnwyEVx
         rYuyGTW8iIa6YOg7rMpSKkm1OOYxVXYGOK2424eGm/FTl+N53KQL1lRpOHf/HXS9cVwk
         IVXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xDXflMGg/2z8rpmfEKz2XLTGBenHxW4qOGAL0nVWlq4=;
        b=XfT7Gwm0b6d7YduofaEvbfZNPX47Rr1kY3j/tIcrD9B+eIgfuJblRd14hilFpqObNp
         rw1ya9oa3NVirH0yX8IFtVdY3jSrG7vvg7Xn0XOoI7aAdHZuHXBcqQ5CMVpGbh4mgwW4
         OMp1XNZ2rxqGKFqsn69Yr+8hUnccO/RZEXqm6NKpxCuw+elaFH5Ubsu1qcpAZG4XGwwe
         Vg1fWUFclUETkxscUUbBhLrI1kvu8BWvrRNq/GncEfXfvyMcE3qKGAprZBgCN9ZSFsHx
         nWvaqkWlV1Qs6y7wnPkJgS/XbTxWdhsfNOHdhqUUZRDhqk++8A1GJRnE3cNTkKEoS4uJ
         gdKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532THQVkbWsEtJSRUGkzi5V+VMvjLNWYai2fa4TnhLKZAEZjlZYK
	wN+eD9Hg4ghA+9D2a5zDyL0=
X-Google-Smtp-Source: ABdhPJy0Aruvn2pcSoTrdmK2kwhMMxAxvhnqc5DUoziUdwFmQLxtWU8o64+N+4LvfG7ZDwfsYSBU1w==
X-Received: by 2002:ac2:48b9:: with SMTP id u25mr7954639lfg.569.1635483637559;
        Thu, 28 Oct 2021 22:00:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf27:: with SMTP id c39ls262875ljr.1.gmail; Thu, 28 Oct
 2021 22:00:36 -0700 (PDT)
X-Received: by 2002:a05:651c:10b1:: with SMTP id k17mr9063727ljn.102.1635483636472;
        Thu, 28 Oct 2021 22:00:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635483636; cv=none;
        d=google.com; s=arc-20160816;
        b=qjdW1wBoUAF2714Q+k/Vev4E5gcAsOMO0whOrYPuPGtj9ko5Pp+61e3jTI+KCWmgG/
         S9+OihwE8t4oWHnGscufXWde+nTJpjzFpx3dwljYCnmiDdzPMh6t1zlGiGCnpxXRm3wI
         QSayAl2YlIEN8efe+Ut/kLIgBjK8QMYAYywyecSMs5yzmG5C7jooNSK24cyanKSkEpK5
         ChidvVNHDkztPixQzek009EU4GOBVMPoYnvqTBs0lMmsGtu/pxVnoBp/i3ipk2aLc5WK
         wXuikjlzdFCJ+Xh7QnwGc9Js3q0rcvX/CafkLcWTKI0vsv5f/Q2+WkY9xTcl6kqZigga
         CqKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fVrxR6rs0QgNgX/0Rgh0R5Yk7RWIkh0KqpodnVxs5fE=;
        b=T64U2oF+9wmROZM0Zjzir4UEs0vuERe/LCpzGdKey7W4Viex/uxHqBc0AmdFAYMx8v
         KPrlEOrsWq/vXXbLdMdXrpxdypHy5BOqo2Ozy8aDWMumZUbZuTyesGa0Y3xVnGPsEfEM
         YiCOaI4VJoIjCSXuIAVC5MDjxnjUCET01te6bKv3qYUYbi87mvLnqYE43eiMLD/kzp17
         Kw2iYiJUxT86ufXd5jXVpNNfS+tM2QCfO2vsq9MB5Lrn3WBoCDXVZ1nkHhLZ093ep8Un
         OIAZF46bO5kEi4EoXDvhLMHGcCAu16b4LJzay3qrAcxLqzyXSgdrs97JxhMRMXAYxUTa
         mv7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=dYEoaswM;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id x78si227740lff.10.2021.10.28.22.00.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 22:00:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com [209.85.221.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 67C953F198
	for <kasan-dev@googlegroups.com>; Fri, 29 Oct 2021 05:00:32 +0000 (UTC)
Received: by mail-wr1-f69.google.com with SMTP id f1-20020a5d64c1000000b001611832aefeso2981668wri.17
        for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 22:00:32 -0700 (PDT)
X-Received: by 2002:a05:6000:186a:: with SMTP id d10mr11818531wri.279.1635483631173;
        Thu, 28 Oct 2021 22:00:31 -0700 (PDT)
X-Received: by 2002:a05:6000:186a:: with SMTP id d10mr11818509wri.279.1635483630964;
        Thu, 28 Oct 2021 22:00:30 -0700 (PDT)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id d9sm712512wre.52.2021.10.28.22.00.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 22:00:30 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 1/2] riscv: Do not re-populate shadow memory with kasan_populate_early_shadow
Date: Fri, 29 Oct 2021 06:59:26 +0200
Message-Id: <20211029045927.72933-2-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20211029045927.72933-1-alexandre.ghiti@canonical.com>
References: <20211029045927.72933-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=dYEoaswM;       spf=pass
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

When calling this function, all the shadow memory is already populated
with kasan_early_shadow_pte which has PAGE_KERNEL protection.
kasan_populate_early_shadow write-protects the mapping of the range
of addresses passed in argument in zero_pte_populate, which actually
write-protects all the shadow memory mapping since kasan_early_shadow_pte
is used for all the shadow memory at this point. And then when using
memblock API to populate the shadow memory, the first write access to the
kernel stack triggers a trap. This becomes visible with the next commit
that contains a fix for asan-stack.

We already manually populate all the shadow memory in kasan_early_init
and we write-protect kasan_early_shadow_pte at the end of kasan_init
which makes the calls to kasan_populate_early_shadow superfluous so
we can remove them.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/kasan_init.c | 11 -----------
 1 file changed, 11 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index d7189c8714a9..89a8376ce44e 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -172,21 +172,10 @@ void __init kasan_init(void)
 	phys_addr_t p_start, p_end;
 	u64 i;
 
-	/*
-	 * Populate all kernel virtual address space with kasan_early_shadow_page
-	 * except for the linear mapping and the modules/kernel/BPF mapping.
-	 */
-	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
-				    (void *)kasan_mem_to_shadow((void *)
-								VMEMMAP_END));
 	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
 		kasan_shallow_populate(
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
-	else
-		kasan_populate_early_shadow(
-			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
-			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
 	/* Populate the linear mapping */
 	for_each_mem_range(i, &p_start, &p_end) {
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211029045927.72933-2-alexandre.ghiti%40canonical.com.
