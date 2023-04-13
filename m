Return-Path: <kasan-dev+bncBCCMH5WKTMGRBR7736QQMGQEHRSWJ2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A54EB6E0E35
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 15:12:40 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id f14-20020a19380e000000b004eae6917b76sf5992132lfa.13
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 06:12:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681391560; cv=pass;
        d=google.com; s=arc-20160816;
        b=dCzK+U/tzVhSvXGx8pMPRkPcK737sW0vaVgOOkrzMOxxs1VXRMI+ZcmeznawDe6EET
         IU1ht6hLOqi4ON9gsRxllCyVlLqMPVqqYu4oZQ+ny52Ac9vfHhNkjpEIkBsutDbiBP5C
         L/axxgCTr8sLBUJ/rd+A2UMs08Nxx53JYHrh3mau3w42S6zoPgzPzduqC1wIU5jNg37P
         1pNhlxqC78Sov5WHjGHHURCZnHVQmTzESn72D6j09Hp3KT8osAdn8rnvg/ZEzu5i3IOJ
         RJjh76GWX6nrdI7WrrUZqaXUWL0QepeO2RUChJ0Rbe7hIUl2k7HvsOWwO7EUAPGGhHL5
         oqew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=oIg+LvEEWXlqYPM4raxYNy9UINvmUpdFMI/ocW7pJqo=;
        b=UdQ7zgiLUD8s5m+SqyadPG2JYHr4aW4J2ICvHF9Xgj1PhvyPE9VMtvMY5rysKxaUeY
         MSUMZZ+HJwJLNWJYTmWC26l/NE+KOpIeE+UvCXQNqNCKSRP55eye0d6+ymcf3TtnTkwU
         xzVHgOb9rVuPZf6ja7RLZo2CDdJBPnbS0JCc8gG2pK/colvf9tFeT1wMfeXLHmAz1IGA
         TPwYFtYxXatblfliyzjtfm3724FutyWMaNzvAmjPlI2wBK8SPoLUIXkkegHDBMj6gozS
         by85nTsz5hghBLIL3Vmoef/WlgDflQP2cU1vKXuDtPr3kHsuxuC1twfxunVXBcWyuuPG
         qHsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3g3kcnsZ;
       spf=pass (google.com: domain of 3xf83zaykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3xf83ZAYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681391560; x=1683983560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oIg+LvEEWXlqYPM4raxYNy9UINvmUpdFMI/ocW7pJqo=;
        b=GnXDhzyJ0EA999J9WrvsLsGZQaG9pN2ExHGhh0tVpzR1OGK56HyeOag986GIguNfti
         EdHTDhAq+CPGRe63x7CgTqgKnrxYeOJRFXMW/78PGCe6hlmcIxBnFUsKdsFHYWB/uNkq
         ZuOPUtgUU9rAsn1h2oBq7oVABN/AU6SQpphJgqt4nwhOJsYECMFpmabMSHAcWZ1tZ9Lr
         Q+uhTV10zvOZPQAUbS7+OTF1LHTVkTAAkiZJwfUsJ3BhTY4lJyvgP6PhgagdlA8R5GCw
         kJ8iH8Mvs3ctACCI8HFXe1jQbc5hbouDwscgW00w+YZigKrsU+2hTyHTzb/fZLq2TFJA
         zjNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681391560; x=1683983560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oIg+LvEEWXlqYPM4raxYNy9UINvmUpdFMI/ocW7pJqo=;
        b=iBsIbNrNea+7y9euhI/YssxjCI94CyGOSzirdzAlYzV2s4J6CAWSlewou6TNURN4Xx
         EmGdd8V5CXguVHGJ4sk4ny5dxrVBM6Gv1XYFHMEKGfInK8yVVlp8WFiaK2lKKz6BENZn
         1wbtb/K0X4FBIq7SwI+Lw/VaLmjr4nnDlax59shJh/gLaTte6iR975uskS7xMusHe8Cl
         llLvLoZDn5uYFAtohYB8cBDvrmr3k5I1qljjn6u+dmHogiCV9Q56XLdIbQn7gx5pdcsT
         ZDFnBqIkMUhYPmBLnhn0LeFCOwO9HWwN2Vky8z+fDmP0U/Z34dQV6ZdcF1AB6R8nifWy
         Y2dg==
X-Gm-Message-State: AAQBX9dw/cnwBp0NMDt9+ZvEyMJ19GPAQaF2VRdngwJnjWglKPUA8uAw
	JTUFceU8BqWijhy2+aQONHs=
X-Google-Smtp-Source: AKy350YJxk/1EJLIUF35S085qpid63XmyD8yetRUFgJnBf8fdUXUapYXKjAVam0Emc0GfEZv3RDxJQ==
X-Received: by 2002:a2e:808d:0:b0:2a7:9f4c:ce94 with SMTP id i13-20020a2e808d000000b002a79f4cce94mr721382ljg.8.1681391559912;
        Thu, 13 Apr 2023 06:12:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:401a:b0:4ec:83ed:245f with SMTP id
 br26-20020a056512401a00b004ec83ed245fls19713lfb.3.-pod-prod-gmail; Thu, 13
 Apr 2023 06:12:38 -0700 (PDT)
X-Received: by 2002:a19:ae06:0:b0:4ec:ae17:81d9 with SMTP id f6-20020a19ae06000000b004ecae1781d9mr666869lfc.32.1681391558476;
        Thu, 13 Apr 2023 06:12:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681391558; cv=none;
        d=google.com; s=arc-20160816;
        b=TXHYpnvJZiGie7jnxOwzzcbUVTMoFtKy1sWWFBpPmRr+WL+LGfvkK2XLOi6nixmUvi
         x0bsOIpt5458TiXmDnMR+tE59f+9DxuPNKMH1nNpyxVeWvTMmTyVdFwibJiE5Jnl0zoQ
         72fZMPlQxxa7md9ZBDhBujoNTPJMSChVun1YdrdTPIipNpZAg5KTgf5uvNV7KyYMFZS0
         +TbXXMwESz5Mp3I681MszLXCtElXQr+Q4YZd68av9tEUMYKeAq60hk97KfljYomn9s0c
         0XgwtDj+aLYCWCphsiN9fx9tG8ApiI3miWQH3Lhe8zAFz8MwDcuZQgpAsKe2SBuE2KBM
         KJEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=5hl8mLgZ8vfFyAYGSuilKL0D92tfM3tv959zGBlMPY8=;
        b=Wa3SNMNe5xUYGKjlx+qr99Qo6TtcY5+FFDYAhCH7nm7KZytce6vnBE08OcQdLRaEyJ
         MGm+Kt9VbNEs7WHtLrVG01vifIXp8cakHS/ldEsDyNiIObW+g0/Wxb/aQ7PxhMzxCEe9
         BnEBcDzKTMP4OObgouj2DqgeWHHseVt8oN0/T+uBFVBC2AfPO1aHSmU+FBozYIR0OhZF
         UYYUXQiAjU9lxQmRcRGGCB1EP4CgsphJLCIzKY/xqB7A4266M1GlGhh9Oj2/S7rC2nbx
         zPf+6fAEbUYbOPZzV5SroqEQhJbdCeeCEVBCxlo2nBOMm7bNh+vOMcHSbEMOXvFpoL9A
         u3yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3g3kcnsZ;
       spf=pass (google.com: domain of 3xf83zaykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3xf83ZAYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id o7-20020ac24c47000000b004dcbff74a12si78444lfk.8.2023.04.13.06.12.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Apr 2023 06:12:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xf83zaykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id e20-20020a50d4d4000000b00505059e6162so2594510edj.11
        for <kasan-dev@googlegroups.com>; Thu, 13 Apr 2023 06:12:38 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:eb2b:4d7d:1d7f:9316])
 (user=glider job=sendgmr) by 2002:a17:906:3091:b0:94a:a6ac:8a2d with SMTP id
 17-20020a170906309100b0094aa6ac8a2dmr1265450ejv.13.1681391557908; Thu, 13 Apr
 2023 06:12:37 -0700 (PDT)
Date: Thu, 13 Apr 2023 15:12:23 +0200
In-Reply-To: <20230413131223.4135168-1-glider@google.com>
Mime-Version: 1.0
References: <20230413131223.4135168-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.577.gac1e443424-goog
Message-ID: <20230413131223.4135168-4-glider@google.com>
Subject: [PATCH v2 4/4] mm: apply __must_check to vmap_pages_range_noflush()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, 
	Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=3g3kcnsZ;       spf=pass
 (google.com: domain of 3xf83zaykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3xf83ZAYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

To prevent errors when vmap_pages_range_noflush() or
__vmap_pages_range_noflush() silently fail (see the link below for an
example), annotate them with __must_check so that the callers do not
unconditionally assume the mapping succeeded.

Reported-by: Dipanjan Das <mail.dipanjan.das@gmail.com>
Link: https://lore.kernel.org/linux-mm/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com/
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/internal.h | 14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index 7920a8b7982ec..a646cf7c41e8a 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -833,20 +833,20 @@ size_t splice_folio_into_pipe(struct pipe_inode_info *pipe,
  * mm/vmalloc.c
  */
 #ifdef CONFIG_MMU
-int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
-                pgprot_t prot, struct page **pages, unsigned int page_shift);
+int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
+		pgprot_t prot, struct page **pages, unsigned int page_shift);
 #else
 static inline
-int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
-                pgprot_t prot, struct page **pages, unsigned int page_shift)
+int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
+		pgprot_t prot, struct page **pages, unsigned int page_shift)
 {
 	return -EINVAL;
 }
 #endif
 
-int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
-			       pgprot_t prot, struct page **pages,
-			       unsigned int page_shift);
+int __must_check __vmap_pages_range_noflush(
+	unsigned long addr, unsigned long end, pgprot_t prot,
+	struct page **pages, unsigned int page_shift);
 
 void vunmap_range_noflush(unsigned long start, unsigned long end);
 
-- 
2.40.0.577.gac1e443424-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230413131223.4135168-4-glider%40google.com.
