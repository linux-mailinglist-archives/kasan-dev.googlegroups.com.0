Return-Path: <kasan-dev+bncBD52JJ7JXILRBKOUQ2RAMGQEB34EKOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FB4A6E9DAF
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Apr 2023 23:10:02 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-5ef4b68f47bsf7502686d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Apr 2023 14:10:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682025001; cv=pass;
        d=google.com; s=arc-20160816;
        b=No340IFiO1drZnuiHJ7bZtnrXUMX0JGY+2BgQes+K6tIQ3mCKHFb00p2GYkwwKZ04Q
         AyBVTxaTdTAKKnKGaTazvDYcQkgcTae7tPSSNnhjSOoYTN0tNGLCWPvFRQiatsGqqcd1
         Hsecwd+B9SUB1LiupQ8lX5bFHOG2yVoFzo4LLi68fQ4AE8PgC02rTxr1gMgOd9lSech3
         HqHMYiqKOKVQIzrAWwqH/JjXIXQ4xPOLJOGS/b8uS9ZJXTg6qkM+fgaG9dESGTCI19Ix
         IJ6lX2tTk58K2q2cbkrOgYlU4vPcBNRmxXANXOIj/XH4k0b6HWsFS8O1VtlG23oZzWGJ
         tzEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pwnoYPPulFB3Lqv1YhVQXpO6UtZXAhw1cC2TGEx2c/w=;
        b=LGtm6huw6aP9E+caa2LUY6T2ALPy8i99k64HPBUUNydNhkLiKr+ZoRcTte2px9Wy1o
         YfdadcsGH8G13gvIjaD84jM/iD+YHTIYLECX7Rk75SURrhr7UWTxYXcP5zalU/dho5hh
         DbUTZk2s86hqHi0xS+FDeZph/F3eeJbqojiIGWxjihRAJ1VG07qY+icqYpKPBFxhcNhB
         Rj7gHh7zWlJKAFO/ADW7ts3wvOYHu4maIa9vYEmsWaWzGNd/9kz9o3j1GoMKZ8AoTX1N
         nGtNJS3sMQu0GuVJgpvHAzopRFWIMOZkNE1JiBoC7Eog9mA8i8gaik1tQEya6z3Jlpsm
         rqYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Tsfu7N3s;
       spf=pass (google.com: domain of 3kkpbzamkcasannrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KKpBZAMKCasaNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682025001; x=1684617001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pwnoYPPulFB3Lqv1YhVQXpO6UtZXAhw1cC2TGEx2c/w=;
        b=Lp/MyHZ9A8aau3pJyweK6bD6rJFHuakkzv2YsA5KDg7Rn3yCMdfrq+Zd4WOK2LveSw
         /4zWYeayGNWMvBTX3NhR9wgLiwGThquNYauVkwoNPb+CkJQO7AZTQ50vU2gdJ/Z3hcKv
         jSZGLqHDT/oW/qm6b4quzBBfeHr/Trx/YGtlOtrU0EwzlOgUz5vOjWHAd1MBqTKAb7R0
         ZdlIz4H7AwBIuy/adEVL0A6eKKc3tF7l0TP1HK+OUWc80L435/ybx+mrQLCKHffspF4E
         VPvSMLiHAvYSjfVQdtRUiqd/tJEH0gQ5mdL0o5tTe3sT+QGvmHXSQpRN6FpqmOd8x2NM
         PcRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682025001; x=1684617001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pwnoYPPulFB3Lqv1YhVQXpO6UtZXAhw1cC2TGEx2c/w=;
        b=ajGCP0+0OVixo0Xrrs0Yo1sJ9BDh1UBRMk1Bb5sxoeGxDyCPahR9/kAYMiryfDqz3d
         HeMYU5P3u/7mwujNjzjOLpStlOrDghcynJnVhSiW86SlAjFIVmlFsNR5pqrbKNNPV0jJ
         f0WR5p+iRNFwj3Ze4/9ILaCOeQGlt1YkN9GmhCbwtniEb0O466pp4iJS9/U4O2CMeIJY
         05ZMoYkZ8gJkloAYX26kMUsPbo1tYFVJfCouXZYog3c6SRQRsVcrgahrRjePRPxdg2x/
         Rz7tk0HiI6yp9rIFiMXyu/6oDBD9zOmMbNoDBgWMpSxlXnASh7pf/W/lz7yI8YsOQzcx
         MtMQ==
X-Gm-Message-State: AAQBX9eRoF/k1A98MX9YreHz8VuLXkxftWIKY4nfmUaQIkVzWzkKTP2D
	HASiCHozr2mNEMJHpzg45hk=
X-Google-Smtp-Source: AKy350b4EvfvUdBreIGwpkp0DQHpRboYoeTMlADND40ptAix3pJOrVnwP4VCh0kOp3FXbgfc1G0DZA==
X-Received: by 2002:a05:6214:aa5:b0:5ef:43ee:61fb with SMTP id ew5-20020a0562140aa500b005ef43ee61fbmr462544qvb.6.1682025001511;
        Thu, 20 Apr 2023 14:10:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3d88:b0:5ef:5927:ca7a with SMTP id
 om8-20020a0562143d8800b005ef5927ca7als2085991qvb.1.-pod-prod-gmail; Thu, 20
 Apr 2023 14:10:01 -0700 (PDT)
X-Received: by 2002:a05:6214:2aad:b0:5ef:3b9a:b01d with SMTP id js13-20020a0562142aad00b005ef3b9ab01dmr4708397qvb.1.1682025000977;
        Thu, 20 Apr 2023 14:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682025000; cv=none;
        d=google.com; s=arc-20160816;
        b=DBqGxcrkjIhLyEqSk+zxqxuNG97OK4k1vFIn+Sv4OKGsZf9R5X/42fRCNjDpUmoTed
         gcfUTqjRNvCcYIBp+Gm6zzb/pRNTDJAfLRkdj9aGrHbOIEIi98AQi4cDSYUZ/+ZEnVN7
         gXZlitabMqS0Lhq912apyPABqV+nwkkMUP2ZMtjH10rNJoBubxZM2ZUGKEoSqZVPBzs3
         FLSrIPTwrySV5u4eudTgZNVrux/HWwRe8YmuyvenVRGBZrMfpiCfjGYl5N2r7WraFpTe
         88Z5y8x8HwkUlNpr4MUwYoZc0nA+4o0HQpf9vudfLAWx4CkVlfp92VT72BjDhOp7yDLk
         klXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=z8h/G6KklbzPNQ9jczk/GigGAZbyVMnEE1fOx6AWhk0=;
        b=QsNz88/vZ4BjvavDz+eZu74ZdRvx29XXBljqqbv6U09JLRKLxH/prGyTqAOB185vA+
         ExzZhDgrhwA7vFF3+c+MClIJQCcc4bES8Ur2n0PQOVWSivXMHkj8TMdi231x2LoSFYJG
         cO/Jsjlmn27ng9L+RNchy6SUlUMnweTIXy9smsGLYvl3Kg6NOeqP/mfa6fbY0tFi84dT
         hDUN4Z6uvXdcbxvKgauOnspL1WsB+8/k6UjIuReTvH/pKfXNcZI1tHjyKrKiCwZWoTFE
         IUHM7muvEEPQrRsMY7o56NzXuL9gjKO54OOIt9m4mqKSBruGhtdGhrPXzXNmsmgA0yJB
         oExQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Tsfu7N3s;
       spf=pass (google.com: domain of 3kkpbzamkcasannrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KKpBZAMKCasaNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id e15-20020a056214110f00b005dd8b749184si149923qvs.7.2023.04.20.14.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Apr 2023 14:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kkpbzamkcasannrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b8f46dc51bdso1408195276.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Apr 2023 14:10:00 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:651e:f743:4850:3ce])
 (user=pcc job=sendgmr) by 2002:a25:e097:0:b0:b95:4128:bff6 with SMTP id
 x145-20020a25e097000000b00b954128bff6mr274448ybg.1.1682025000734; Thu, 20 Apr
 2023 14:10:00 -0700 (PDT)
Date: Thu, 20 Apr 2023 14:09:45 -0700
Message-Id: <20230420210945.2313627-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.396.gfff15efe05-goog
Subject: [PATCH] arm64: Also reset KASAN tag if page is not PG_mte_tagged
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, 
	"=?UTF-8?q?Guangye=20Yang=20=28=E6=9D=A8=E5=85=89=E4=B8=9A=29?=" <guangye.yang@mediatek.com>, linux-mm@kvack.org, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Tsfu7N3s;       spf=pass
 (google.com: domain of 3kkpbzamkcasannrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KKpBZAMKCasaNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Consider the following sequence of events:

1) A page in a PROT_READ|PROT_WRITE VMA is faulted.
2) Page migration allocates a page with the KASAN allocator,
   causing it to receive a non-match-all tag, and uses it
   to replace the page faulted in 1.
3) The program uses mprotect() to enable PROT_MTE on the page faulted in 1.

As a result of step 3, we are left with a non-match-all tag for a page
with tags accessible to userspace, which can lead to the same kind of
tag check faults that commit e74a68468062 ("arm64: Reset KASAN tag in
copy_highpage with HW tags only") intended to fix.

The general invariant that we have for pages in a VMA with VM_MTE_ALLOWED
is that they cannot have a non-match-all tag. As a result of step 2, the
invariant is broken. This means that the fix in the referenced commit
was incomplete and we also need to reset the tag for pages without
PG_mte_tagged.

Fixes: e5b8d9218951 ("arm64: mte: reset the page tag in page->flags")
Cc: <stable@vger.kernel.org> # 5.15
Link: https://linux-review.googlesource.com/id/I7409cdd41acbcb215c2a7417c1e50d37b875beff
Signed-off-by: Peter Collingbourne <pcc@google.com>
---
 arch/arm64/mm/copypage.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 4aadcfb01754..a7bb20055ce0 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -21,9 +21,10 @@ void copy_highpage(struct page *to, struct page *from)
 
 	copy_page(kto, kfrom);
 
+	if (kasan_hw_tags_enabled())
+		page_kasan_tag_reset(to);
+
 	if (system_supports_mte() && page_mte_tagged(from)) {
-		if (kasan_hw_tags_enabled())
-			page_kasan_tag_reset(to);
 		/* It's a new page, shouldn't have been tagged yet */
 		WARN_ON_ONCE(!try_page_mte_tagging(to));
 		mte_copy_page_tags(kto, kfrom);
-- 
2.40.0.396.gfff15efe05-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230420210945.2313627-1-pcc%40google.com.
