Return-Path: <kasan-dev+bncBC7OBJGL2MHBB34XROBQMGQEGYZB4PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id A682934E198
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 08:57:52 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id u16sf4635280pfh.20
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 23:57:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617087471; cv=pass;
        d=google.com; s=arc-20160816;
        b=fYXUW3O/ZPBZJf6eo39+SR9E6evC7c0+J65A1DmEpGlvIUyh6cp7APzv+MtfTzuqTZ
         Y6iHjCC+SyIkoQ3bciTn66Kih50DhAzg2rOqllig5+vYDKhIGhuZsE7Shc1hRdsb600t
         tC7sIUg7buAFUeaEi6r3+O0Sf6eTDsFdjRT0mxcyQWAjyXwGZFzz2koI3jgrCWcEGlr8
         v30ZLJYnXWDfQsb9iEMOXIVs+jRrOsMDKJkaZxNkU4WXp4+L1GMhDdEgSU/gEjtqDnIM
         ZbD5aK++wukYJyLhf8addecCDemw5nvcgeNIxmne6TggoXF+6msRa2l1XZ7gu/Le6dpJ
         yonA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pLLNAhkC2iD5TnGc3YWGgoJeCl9WV9yShjLD9/zVqoI=;
        b=EQ+Ethv/8RQfgLInx109hdlZOvnjbxHmT0RNX8vpZsLgPZjjacJWruyg3LtKzzGquG
         k0KtBXRuQ5e5XgsIfqBVjRkfRhmymj4wc6PUVK8VJg4AC8Jizivwuz4o+tKOMHXeXtWj
         FCPpia46DQ4SH46vPXe1zQVqX1fed/zJ0cGqz0xtEryjz7nLJXRug0XSvapvJfIY+RqD
         TKCMIYnoQjlRLIUq3mCjhVpuTNhItib95iSeeZ9kZwqWSX6US/6BLG/KAV988sYSHwcc
         9WFSjzSyyFLxYkfXpUR6ghbJZAzTkm/4li3Ocd0Rymz+NP36aKq4I/CdJ8TG/czdbfoH
         u4AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OH5d8xlZ;
       spf=pass (google.com: domain of 37ctiyaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37ctiYAUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pLLNAhkC2iD5TnGc3YWGgoJeCl9WV9yShjLD9/zVqoI=;
        b=nK39gRJF7jBn8FYC72gAU4F9LWHIBfeA6EAUf8G09yI+7rQNdffzGs2V2+4ILuV8cy
         mxW/o2nYhG575lRhZvM9Dd194UiZSpvvYllMrv6spGiGDVrITYWosAfoK2y2XXpScEEU
         u5UrOXRAiqscn9XzmD95DJO1pg2qPgq5WtDvKxb+Zns+Cs9H5ZuFmKslZs4VTSu0Bpda
         nLKACYCjq0BZz/Jzbyj1dPECZpXa/U/he86G9Fk6etO501BSAhBXl3Cm6b/cOPRKMgr7
         8o54yjM31edkyyPujmR9Wc71ao1u/lV++dzhFbjQHNL62oI0Uy1jPoZJMYnIJ3/6yxEJ
         7j6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pLLNAhkC2iD5TnGc3YWGgoJeCl9WV9yShjLD9/zVqoI=;
        b=MSJKLWnmy2OTBFPJHGiz6inBk0Wt9RKz0ekfowQuxA7/MT5xOhXb2YSqay7AFNNj4/
         lHi1/ZEbmTicRiyrvZpPrfFnPuGkyx8jJC3UWJZlR9I5RoEP2yAOuVR9aCZ0DjmUNnSt
         5mVi/zjn0mjeBZOA35e4Yvn9dCp8AKiOb2YoD95DvNNp9kitou/+OfyfwtxF+w4vnoMz
         1vb8r6s4LqM5MV8/B9HCwZh3rBJLv0FdCnTPyuZa4OsnSwJ4glAVtjcgTExYtLVv2NxI
         JX0Q2iq6Wcc39o0IOegxAsYyUYGA6md3E0aj1f09aoe+gALKMki7xkag0PS33hThQBft
         AZJA==
X-Gm-Message-State: AOAM532YBWJ19TCE4/8qtigcy7kAXwhFGv1hy1C7ehzxtw3CCWIuEWZu
	0k04cG3waDXff+egXR325W4=
X-Google-Smtp-Source: ABdhPJxOicyPq3/FNKNB2VVmhv34iQ+VkQdGrrvf2bjU6J79NSm4bQakCuy4OPL3SaB4pjH89iiyzw==
X-Received: by 2002:a05:6a00:8c7:b029:20f:1cf4:d02 with SMTP id s7-20020a056a0008c7b029020f1cf40d02mr28962815pfu.49.1617087471156;
        Mon, 29 Mar 2021 23:57:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da86:: with SMTP id j6ls10265201plx.8.gmail; Mon, 29
 Mar 2021 23:57:50 -0700 (PDT)
X-Received: by 2002:a17:90a:c289:: with SMTP id f9mr2915903pjt.105.1617087470565;
        Mon, 29 Mar 2021 23:57:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617087470; cv=none;
        d=google.com; s=arc-20160816;
        b=NxdrLQJo3/bKsy1tA0hEXy4Xsh9yz24TpcGeQF6ddx8bth6za7gbLR9xr1UHD8bren
         UzcPD/Vh17h7+bFRpVnp9ZC6CUVN+Wzz48EYCs6JFECuL++VDU0yy7b9+EACXsSq6FqR
         3Ew2kWYRjNozaFrKxNnZraUVAXiU0mDu725eeh8Qss1Myvfii7g0VtprJ5ENAZmxP8dL
         Xpa63wy2CjZ3ceDq4dTTzAN7uLUQHsU9NL/YMlqbTDtByIHTowb/qevKnVzoJv22OAbT
         03Nh8xS3w80Wj7foIAYu1xp633qWfep7cGGnsHMUyba9GQ6cPwF4nA9unFnq3DZsEMuH
         wciw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hMimholtJavSZ5k5RmskDIdPrM99sfcyiNVXiZ0C39Q=;
        b=MRHcI3/nrek5GobZN5cpau330T773i7d6DaxjouYPeSKmO0jhClYMH6sXiaarVBwUw
         LCM5cfjUFKqszayM42Bl3sft4tkdFPZHT1gSApxd01z8JUsV8qNZwN3todLm/fCBcjrm
         RnJg7u9p06bgUqAWzTWK2UPOqexeyLImfgYURed5SsexhsoSa3Wn9xuM7yvgIDE5YrW6
         QMUwRwv8mS4uQ9C0tHpInJxHtTSbaYYZnSmKvluNISXyLTdyhyATIM8sw6Ff1U4BaFCj
         hDexik1xmdU7PFuoCzGAveZYHRko5w1p2b5kEEjjhntBy0yUyT1tk7t3aDif7iJxT0wN
         Dwdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OH5d8xlZ;
       spf=pass (google.com: domain of 37ctiyaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37ctiYAUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id nv12si68864pjb.3.2021.03.29.23.57.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 23:57:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37ctiyaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t18so9118807qtw.15
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 23:57:50 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:40b1:c44f:3404:ad6a])
 (user=elver job=sendgmr) by 2002:a0c:e148:: with SMTP id c8mr20761637qvl.18.1617087469699;
 Mon, 29 Mar 2021 23:57:49 -0700 (PDT)
Date: Tue, 30 Mar 2021 08:57:37 +0200
Message-Id: <20210330065737.652669-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH mm] kfence, x86: fix preemptible warning on KPTI-enabled systems
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Tomi Sarvela <tomi.p.sarvela@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OH5d8xlZ;       spf=pass
 (google.com: domain of 37ctiyaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37ctiYAUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

On systems with KPTI enabled, we can currently observe the following warning:

  BUG: using smp_processor_id() in preemptible
  caller is invalidate_user_asid+0x13/0x50
  CPU: 6 PID: 1075 Comm: dmesg Not tainted 5.12.0-rc4-gda4a2b1a5479-kfence_1+ #1
  Hardware name: Hewlett-Packard HP Pro 3500 Series/2ABF, BIOS 8.11 10/24/2012
  Call Trace:
   dump_stack+0x7f/0xad
   check_preemption_disabled+0xc8/0xd0
   invalidate_user_asid+0x13/0x50
   flush_tlb_one_kernel+0x5/0x20
   kfence_protect+0x56/0x80
   ...

While it normally makes sense to require preemption to be off, so that
the expected CPU's TLB is flushed and not another, in our case it really
is best-effort (see comments in kfence_protect_page()).

Avoid the warning by disabling preemption around flush_tlb_one_kernel().

Link: https://lore.kernel.org/lkml/YGIDBAboELGgMgXy@elver.google.com/
Reported-by: Tomi Sarvela <tomi.p.sarvela@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/kfence.h | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index 97bbb4a9083a..05b48b33baf0 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -56,8 +56,13 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	else
 		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
 
-	/* Flush this CPU's TLB. */
+	/*
+	 * Flush this CPU's TLB, assuming whoever did the allocation/free is
+	 * likely to continue running on this CPU.
+	 */
+	preempt_disable();
 	flush_tlb_one_kernel(addr);
+	preempt_enable();
 	return true;
 }
 
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330065737.652669-1-elver%40google.com.
