Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIEBSP6AKGQED3YGYMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 89E1328C318
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:25 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id f14sf2552838ljg.18
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535585; cv=pass;
        d=google.com; s=arc-20160816;
        b=l9PHT9EWVYoOglrB7Rk5cfKWDNdvTm4qZYqwN5YTBQLU2/ROskeUXCBkWmu55s8pxC
         wyfvQocg58VmrVqmzNTTo344DqYYpcgxIdpF/1811+usIOseaOY7g3E0ugwqn3GPgKXo
         F3iwfs22sVaIdnkyo6J6d1SVD2M8POrWFyVPHU462WfpYpd3R2629c3/9uMIsVACNZWE
         ONVukkTXqKPva1UrBs37gcW+lrfMrwCUp6/Ko0agrzW/6l0lLXh3/A6ieUXE2WQ7eCtw
         SqUpV/n4zYlI93JfTdi4Y4lQVANzPu1CliIfUN9TUpET2mntL9YAekzHCDObDTSNLykT
         fWnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jjajqFtdTvI9rrjen+3ibM55ad22wYM1KQIDG1pwAQc=;
        b=Fe7P6OiaGJuUnGBKvry2cY8wVD0hsYzPhjTUm6+GoHRivGyADTQBPOKZKevkUxa/wD
         VN9PWKjt+jAdSZxkFD6t5Tj9mtMF8Dtfi9ibEc2hWrtqXpRPFnzqugrbcef9vShzvzGA
         t6c2MU5B90MLYR4rypAszDDl3RlXQ3BAhOSCQsYJ6FQzQdDKmiqXO5gudanqaCC3g1Xr
         CLuhU5pgG4pBEu5HjF1ivIhY6JbFicZvMcANYPyxT5tbjtVkKwqFoZ5ykIJZidnol3HF
         1tZUoQhQrHlMtYzRQ90Xz3mmv4hbd/nKYYI1IwKxgT32Z/PXohFMOa5eeAf/WNDIcr0X
         4vag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mFABbiV5;
       spf=pass (google.com: domain of 3n8cexwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3n8CEXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jjajqFtdTvI9rrjen+3ibM55ad22wYM1KQIDG1pwAQc=;
        b=DfqCrTHyMSOq5tMyyK82M+m4okRRw+WXzgeW+rsGCM11iWigEzPAZzDBH7ZpLDLgbs
         i68rOxVP1l3Ia82iEAe/f06820cU3AeRdwUcoO7LjvtwOp64X2M5lxwKN2Rf1waMefO6
         RAPn3ZyiLnqKU+UiKb+uuKEtLAUs9VKNuKylNq8qcHQXEtDMn2pX8XjI1BVlya79fJ4P
         MIMb940vxj+Fea90HtRF97W8CTidc7veI2l1pxlX6c1ggPGMjPKUUZ+pgr9tz6z2lY2D
         xsa4NwORv31M5IYn1DQ1GsMIk0yORmCb6o82xPIaFVkLNZ8sI1iuH9uXBNE6qiUzV2Qf
         VFpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jjajqFtdTvI9rrjen+3ibM55ad22wYM1KQIDG1pwAQc=;
        b=fuDpEFLh+i+W3u/7EKHBbMVjQX4MK2oIi61zvqv2tkKJ++Yv2r7gs80TZiH7D46anP
         Xi5L6Zk4NxBNc59IZTviiWmwP/ukQI9RXTZaS3BMJuYR/hM1fE1SVcDrJulvh0i6lNR3
         qaZr1ylFZv2KEh94ZJqVkIDOYjPlkJbwVg2Di8n8WOgyynstDEpZ7yKZSg8RTbZAqEFB
         OkFzD3mzCZjt63XV6jJ7j6sR0caJ/kwrXGDmiQhGitqXfh1zyfB2FCaZy7g0IlKVxPXF
         uVeMZZX+EpadPi7/sKrVA1WalrAINMkSvPR+IRJuRPBlzWi37kKWiR3Z7kjXMzRdhDor
         wfZQ==
X-Gm-Message-State: AOAM532Dfcj8N84wJe9d14tcGLSqU5iDh4VV79pM6Gsit7VSlvsm23ij
	nVbeqrz+yAfpgfSo8zjkh1w=
X-Google-Smtp-Source: ABdhPJz2Z/hYURKap7qf2+ZLNM6/dfmmAF1yS6/AKHeau5vh6z50ju4G1cWG+2Q74aQjf0S/tXsfaQ==
X-Received: by 2002:a2e:9f4d:: with SMTP id v13mr8453149ljk.379.1602535585126;
        Mon, 12 Oct 2020 13:46:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls833291lff.0.gmail; Mon, 12 Oct
 2020 13:46:23 -0700 (PDT)
X-Received: by 2002:a19:9143:: with SMTP id y3mr9506028lfj.104.1602535583872;
        Mon, 12 Oct 2020 13:46:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535583; cv=none;
        d=google.com; s=arc-20160816;
        b=UMm1dj4NqP/Md5q1lgDzEk6RLoJYwHnyqZwvg32BdhxMUHLvwSl9h5mtMfDBfmMuVK
         pMjansBhR1fs4M6ZVwCaaEIenhENapBBKDM7X7x8s3FB2yBF0StFpN96DRpoGgJGKBtg
         NPDDHm4/ls4DQQ/fDpqedSKa6iILXnw33ErueLYt+dbifs4x3k5XnD/+AQJiN5qKO4jl
         hHbLCQxsyZbBDFw9iZfARtz1+J2pBB2xnHbp84MTkZNxpBFCaEvwZ0lO9dturGy6ivZ0
         rg15vQ+kHEnDmfdqfVn++Wzjd4kQJQdj4bd3aU+7+nmL3h1biTfjuyx5p65HO0WGQgy3
         jWVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=WBTykbiiMY/bXp2oeCyvW80uwSDd64COK/UOrsDrX9o=;
        b=yHAKBpYOCl7gsocZyfyRIBYkVmljpW4sLfDExRdpNarGgRYf2ZO+9HZ3prAX/ytimM
         IxKSRHsSaexOxXNC7jFKiXQ+MJA6Y0zZHeVx9MD5KOz2fODtZyYTRp25BIHjG3m7M9PT
         U0Tv3nhJh5KP+wU4Q5SK64FWyZrezLltSNM6wNLnz9IDueQfuYxSTi1zIScWeRTzEjbT
         ufaGjxAxBUhdaaEUpoUTKO8YKHOJfmtuYXQVYdbkPuW08ZlQZ0ebvHblPrGNed89hgln
         DHj4Q8J65fKtX45pufdrKZgvJrC/Epq9UwKvqvAzFEys3OWBPRSH/fo7mpkhwpBw8uVL
         L5PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mFABbiV5;
       spf=pass (google.com: domain of 3n8cexwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3n8CEXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id i16si162794ljj.3.2020.10.12.13.46.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3n8cexwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j6so3802411wrg.20
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:23 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6a51:: with SMTP id
 t17mr15497106wrw.80.1602535583350; Mon, 12 Oct 2020 13:46:23 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:44 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <5dd7ecbd021ea23e92eacb251578896497314076.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 38/40] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mFABbiV5;       spf=pass
 (google.com: domain of 3n8cexwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3n8CEXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e28d49cc1400..8d139c68343e 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -132,6 +132,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5dd7ecbd021ea23e92eacb251578896497314076.1602535397.git.andreyknvl%40google.com.
