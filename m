Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXP7SEQMGQEWUMOU5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B65E3408A58
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:36:22 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id v1-20020adfc401000000b0015e11f71e65sf119464wrf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:36:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532982; cv=pass;
        d=google.com; s=arc-20160816;
        b=uaxdvXxrPztmk37Qsij9IBc12SfIwYhrmXFlCZVPQVXuuXCUuq/nGWryaIymBLLKyn
         WZpxJzxIGi6ntR1dlh1Kk677TyzUXAeomCxI9A+r/qXckM5eESCxYUptT4sG9Q2aFxpb
         225QJm/FHSYJHrM68fBEzYANOK4XRduadS0hDPrQBruKiUFsK+Hzw/d26d5Hhy9ko8RF
         QYLoyEeu88Qmz0O5tsuLnQVt2RWJTgGSAt6qI269aBj6nulNBNinHMkFvFUywL2Y4IwR
         LTsdTyTHARZViulRSX1y1qwCg3rpkubN9Qeq4WGzyf+vfijWgbIg427y4tc9FvE7+J3M
         CZgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=14zq/X/QH0QU7CtzAUHWqyDOAf6UCvEvYBtmHU5N4Vs=;
        b=w6PwBUcUk7Jobxuh/yoZlfU5ZODK4n9vg74gzYFmEElz06FAskxX/WWHlHqs2bigZf
         SVhSZmTocZrx0M+pMLOrTGruKNJwzTHDY/Plwkq6wtTTRpTi6eNNgO7yP0U34aqHtdYQ
         UvzDNQnTOYnKr+0GCS6UL5RpSQ4ZAkaJsJGCkbbiRb7GG/YP50iDrJU1sgmPNJB0TJ8a
         W8GAqQPpJUMYA8yAFttL42bkJUwPZVwczwW5wCOgB7b2cijdvT1PD8kIWagr66boLAw+
         b98tbg8lSPpGW6k4qnONNMQbJoWuRmvFiTbs5dUoHiTS1AWKzMk8MVIqIfy9e+CUHZQO
         u/0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n6H74Ola;
       spf=pass (google.com: domain of 3ttc_yqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3tTc_YQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=14zq/X/QH0QU7CtzAUHWqyDOAf6UCvEvYBtmHU5N4Vs=;
        b=ltWZdr4dgl2dte5hxWW1HT/bW5EFLMGqFepAHNLCVYtEvf02ZBmWGLWNXMDvkdGT4+
         7fxH/snGXzdP5Dw0aPZhcZMp9cKSzySiINQBj7liQRXC1cbZBaJa43rL9meCPSt7ms8R
         +K88WCKTl6U4nrafe09fP4UbqOR2//9adsBVfMBS0WAlPb8HzXzKmoEvC5vFd+Ciwti1
         5JgbCM8WM3LhPdkRvyD+0bw8Fh2pvmMt2fj3snnuRjeXvb7o8WLtVt789GWt9PudVzl/
         /2yzJs80Sw7v86ILitL66VNYD9kRZP5uZXqCx8oTvxLfBSfoQl9wOBrJ2n6ZTu6qbOBh
         qBww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=14zq/X/QH0QU7CtzAUHWqyDOAf6UCvEvYBtmHU5N4Vs=;
        b=l1vA3uo4CViEZ4yDO+jrMIVsKy4hgeXJGcSaObcAHDIevwhGhtGBrQePXQiRjTvTFw
         v+iMwv00tHfYBbYvN4NcO/eoKb/g39tDC1GwJ8jl2BauAq2XSikyNEhye1fc80JHt4cd
         NDK2pdeH2+zUbpXj1tnBy2Hq9Qi5E+wPlr21esgIvVEMTObJ7uEU1yidfKkKREWQ+6IN
         x52/5sasq5hUvCcJFAY9cT0hTSz3QqpsLksnR1dvzDx6qK9va3J6h6FsdIhuj8/6q9P8
         SABr6zLhWymclH3WEq4B6HU3xIZ7jwracC9MgCl3DZDpy2XC3QNrfuhyvN5y114uqYgf
         82xg==
X-Gm-Message-State: AOAM533N3GFCsMylSwS0p19OAnkC1LzZE+NPOV7mhpf8CFS9LkRZn/Mr
	hD2HefjskEuct3uZM3Wdey4=
X-Google-Smtp-Source: ABdhPJwkZTxcU5oCD/qlRb/JDrGJKQ+lDmy83VkyB1BcwEQK69eIsG9trT+SwAAe4JUzp17gKNTyxw==
X-Received: by 2002:a5d:4a4e:: with SMTP id v14mr11929101wrs.271.1631532982480;
        Mon, 13 Sep 2021 04:36:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ba86:: with SMTP id p6ls2459315wrg.0.gmail; Mon, 13 Sep
 2021 04:36:21 -0700 (PDT)
X-Received: by 2002:adf:f88d:: with SMTP id u13mr12180019wrp.297.1631532981475;
        Mon, 13 Sep 2021 04:36:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532981; cv=none;
        d=google.com; s=arc-20160816;
        b=puagH7g+NaGtmdBGNv3NuX9lqJsQOvr1hBrHBjm/Ym5PS9T5Ga552rxQtDnHP5A+6Q
         PXfPZX6Pe1JH718LfEjTPFGsmqvaFCbZI655VMqFjue6O2Qq2nqwQoNl1GzQepcQ/GKM
         EMalF4THC0/q27UoIDkK5sI00XxmHW82Kbo2oDuzl9OhxYGgUZggUheoCvQz5hygY4IS
         p00/oRpjIftxGCjIU4UWrQuxQ+txHrIvWGLxBgiU8oOZPSTqZswQYyIMbgD8b0voHnNJ
         yI3NEKS6Am2ObKL0SB4/L4TiVu3l9fvFXNhC4vzEEDkZmrNQUxCEcYjap9RNK+q//ZKl
         miUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=bSTKtlz5vNtVKimr2bFb/fQDhWY54+Y9NMMcBs2WGw4=;
        b=CVR26h6cIos+oTTd0SRvh8SCfZ3zLgqLAmVc+xsQhUj9VPVZza8zlUJTDQG8Z1Q0/0
         B0mlH25G0vSidbaao/Dzsy7rQyFr054z1pKpEd8Lxd56zltD5zdtOP3ajJltfPXW9fDT
         ++n7/BK1wYAT7DQ3hcXGsZOwUX5P9I7Nn1TG7ikx++436Zv/DpfvrzT3jlTwfxfYaNVF
         rbXT+J5VPacs8ZehwgDJtfvfAmVplv57c288A4Q31lj1RWN6u5KWyzpsgQxLS3Hwp+eq
         OnaRO2bHvXnH6cqE0BiDg7BBOGoMrsGFbT8KA1Y6m8INFi1O3cQHhZupN92IARRmxhbR
         RA4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n6H74Ola;
       spf=pass (google.com: domain of 3ttc_yqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3tTc_YQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f20si38955wmj.3.2021.09.13.04.36.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:36:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ttc_yqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id c15-20020a5d4ccf000000b0015dff622f39so835910wrt.21
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:36:21 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:a05:600c:3203:: with SMTP id
 r3mr10555555wmp.175.1631532981131; Mon, 13 Sep 2021 04:36:21 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:35:43 +0200
Message-Id: <20210913113542.2658064-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH] mm: fix data race in PagePoisoned()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Will Deacon <will@kernel.org>, "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kernel test robot <oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=n6H74Ola;       spf=pass
 (google.com: domain of 3ttc_yqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3tTc_YQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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

PagePoisoned() accesses page->flags which can be updated concurrently:

  | BUG: KCSAN: data-race in next_uptodate_page / unlock_page
  |
  | write (marked) to 0xffffea00050f37c0 of 8 bytes by task 1872 on cpu 1:
  |  instrument_atomic_write           include/linux/instrumented.h:87 [inline]
  |  clear_bit_unlock_is_negative_byte include/asm-generic/bitops/instrumented-lock.h:74 [inline]
  |  unlock_page+0x102/0x1b0           mm/filemap.c:1465
  |  filemap_map_pages+0x6c6/0x890     mm/filemap.c:3057
  |  ...
  | read to 0xffffea00050f37c0 of 8 bytes by task 1873 on cpu 0:
  |  PagePoisoned                   include/linux/page-flags.h:204 [inline]
  |  PageReadahead                  include/linux/page-flags.h:382 [inline]
  |  next_uptodate_page+0x456/0x830 mm/filemap.c:2975
  |  ...
  | CPU: 0 PID: 1873 Comm: systemd-udevd Not tainted 5.11.0-rc4-00001-gf9ce0be71d1f #1

To avoid the compiler tearing or otherwise optimizing the access, use
READ_ONCE() to access flags.

Link: https://lore.kernel.org/all/20210826144157.GA26950@xsang-OptiPlex-9020/
Reported-by: kernel test robot <oliver.sang@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>
Cc: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
---
 include/linux/page-flags.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index a558d67ee86f..628ab237665e 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -206,7 +206,7 @@ static __always_inline int PageCompound(struct page *page)
 #define	PAGE_POISON_PATTERN	-1l
 static inline int PagePoisoned(const struct page *page)
 {
-	return page->flags == PAGE_POISON_PATTERN;
+	return READ_ONCE(page->flags) == PAGE_POISON_PATTERN;
 }
 
 #ifdef CONFIG_DEBUG_VM
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913113542.2658064-1-elver%40google.com.
