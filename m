Return-Path: <kasan-dev+bncBC6OLHHDVUOBB27W7KKQMGQEMGAKNXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 96E37562FA6
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 11:16:29 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id f8-20020a17090ac28800b001ed312c6fe1sf1149311pjt.8
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 02:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656666988; cv=pass;
        d=google.com; s=arc-20160816;
        b=huQnNTCN4xYUHe2eZRphEzJRZ+upfD3boTkMRpjM1vLAb2tUCwR1ZhCWNpIJ7zN72l
         yud1fFrsn7HNA+cP/hjRewLV9tYdiN40Di706gowEm8XbusN2HDhYgAa3S6EHqCYZui/
         rkUbdrXPZyqOpryoIjMShFOEmRh6DQPxQiZY/SdbsNaHWg9WGfdyBFc74q6yaq2tsmjP
         YmiiLuF7zAXK9TNA/JCKLnPnGOJmfMnx+uOIlY4hJ2/abmpec4v/YfCKHN+96OkKMID5
         9U3BB3DtCg057QEKf9SLt19vSbPKxyA/22L+B0AMzTe2TuHX1VVehmPh5CZsdHJuLSG2
         s6tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=x2pg+QeLOIt2k+2DWe1O/wLWsu2rUFOv1A1odBa554s=;
        b=M5zR00mwGjOrtAa5WYzjGqYQow9I5E716KDI07o4vx3MJFEZjB1r3qMuwRZCw8V/1z
         WYUJ3ne0IREelJcDCOl67/7FFsExndqdCTVDik1gkn65dxAcKu9FIQmw1igP4TVvuGZf
         vuiOLY9dHybwXriw3D6PTKYlxq8pwSDR2sMrEe0fy2iwaMslEnWJOAr5tPR6zHp9QRdW
         YrRjOj4jHbtm3Bg/IofzTHCo2kEf7O2s885ECwejjHYsi6TovForj0C3imf13d2QLuzm
         jG78D8BeW3S6FMhHOrjkcXOWSWFDLxq78wydP0aA9ddFXhkivspSsvL7R0SvftZFVgPd
         q94A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ziw2qAXA;
       spf=pass (google.com: domain of 3aru-yggkcfcczuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3aru-YggKCfccZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=x2pg+QeLOIt2k+2DWe1O/wLWsu2rUFOv1A1odBa554s=;
        b=U7R7CtN0ShZaqZHJgLkzLDBKRZyd0n4mOWLTGJXlsq5Jluwji9BT7pO6wYKsEmZFG6
         Akz5qkxrEe9hFSOpX38/8TnbFf9xHAtZSoMcFuImsk4YSLuwY00px+QSFWlwhKC3H95r
         xjsv2BmWps/odTijh/rfK4alQuDlR2ahC4R3vp8QItFAdVL775HgfmexWvahGJEoanYk
         TpViBAxnVsik66uVWxyG3kbSSVDPL7RzmdEYQ4mIcrEeUx33yEgVM/ffd60jVExbeuT5
         3vJFjPL1dgsw4nSGAB8ceHxEBkTEkF5jhhCaciGnPrDuagZqT/uTH0h47aL/4CGP1uUu
         F0cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x2pg+QeLOIt2k+2DWe1O/wLWsu2rUFOv1A1odBa554s=;
        b=M6XevEKXZa0XzjkbPgzQ7pmfwBaAHWb9vEAzOGsp5I4dqGRoXICWHzuB9JoxG0fGxk
         2zK7y0fUlr5J0fGXOxLcRsS+y2D8GI7y6ZQ2rC7PDVCvQt4owHANt6mXAnHOLz5OPqHw
         1ePIcs1mFUiCl7VlZ1FuT2E9MMGBxAwyKJXYFSR1dudrkARMfB/00Zkkjbxhn0h7h0QT
         LwzKIA9rpAh63Iz8EmmIS5roYxkqeJjHnGLVw2Y2eC8BgVY0qiaHcdLKGYeU4cktTA8v
         grOj+uaGnX9dm41uYGpsVJyaTL+iImcMCF8aFVIyn+Qx6YEL186kk1vNAO8a1fU0ShFK
         ECRA==
X-Gm-Message-State: AJIora/Kjd/FzannpfOTwVfXNvFnjkIa9tjoifA/k/U41c+BtYnRIPzw
	cpdzIvc80C0wOWIm15lfDzk=
X-Google-Smtp-Source: AGRyM1sG2ovyh7kaXgInR63x58fvMPKNJaUdC7f2DFsVgjSMQG+Tb37ZaYaBg5Xmsc8UJUHHxxc3bA==
X-Received: by 2002:a63:7a59:0:b0:40c:8f3f:8a7e with SMTP id j25-20020a637a59000000b0040c8f3f8a7emr11354420pgn.582.1656666987805;
        Fri, 01 Jul 2022 02:16:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:179d:b0:505:9501:adc5 with SMTP id
 s29-20020a056a00179d00b005059501adc5ls18874591pfg.2.gmail; Fri, 01 Jul 2022
 02:16:27 -0700 (PDT)
X-Received: by 2002:a63:d013:0:b0:3fc:e50f:8e2a with SMTP id z19-20020a63d013000000b003fce50f8e2amr11364238pgf.283.1656666986942;
        Fri, 01 Jul 2022 02:16:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656666986; cv=none;
        d=google.com; s=arc-20160816;
        b=bVdINXwEKnWoMTb3JMT3YngTMGKZ2srd5xchZX4sWrl6JHJfzNtY8GLeXEG7NpPQNG
         78JicpXzwpugbOf0gGaCq/QrS/+O1Up+7ww8h+9f+8GxZ6qXInPgH+K+PcJ233WEqdXH
         AyQ8HPTu0gw8ERgGjGQPZiAgxOL7hc0QxdkTxuOWR6skAOcgaT3xsnFWM9nr7r12eza0
         SlEJa/7+Vgo0/wk6XcnmN24RIX83xIwL1m3KyeEv6/k/IxPacl94t4LGe2jQK+B3XEFS
         4OJXHMo9Yb7VLag7o6oEALXd0i26PeIEygqt/pZ0Sc8C+CZASO9Im8rU7g6A6InQGbNy
         ESMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Gzf9MNYfzuExJ4letAUuWlfZz/ymERxaYUyT/EuC1fc=;
        b=kQWPuWddUs0tnZso6bW+XFSrFnUOtMhdbaGtlZQ2kan1wRdJ6OOKdLsxPWvUUEnbtj
         L6DcXmg9PWE8NLhrGeHivAP72xCIp09jsajINQVQhPvk3QNavH7RyYvpMDc9kfJOKRJC
         jDiiWufTxR4j3ZuBbSUe6hND+EAdbX/f22dMW8bGKlvkCIGqCa7jtxg5/DZsTrcpts3k
         huSq+u9aOjR/bsyORKvn2L3/PKjzwhncHgXjcDY2yYNXwiQTukG5QdbQO72DL/dfMsNR
         dbTYxTy0P10JOhwul5TZKZHPX01yCewmFnvoh8YGE4leHX+R5/c/qeE53BwnLi21KkiF
         2HAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ziw2qAXA;
       spf=pass (google.com: domain of 3aru-yggkcfcczuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3aru-YggKCfccZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id ix19-20020a170902f81300b0015f4527aacasi848694plb.4.2022.07.01.02.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 02:16:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aru-yggkcfcczuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id e8-20020a17090301c800b0016a57150c37so1189205plh.3
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 02:16:26 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a17:90b:4a42:b0:1ec:adee:e298 with SMTP
 id lb2-20020a17090b4a4200b001ecadeee298mr17874949pjb.161.1656666986727; Fri,
 01 Jul 2022 02:16:26 -0700 (PDT)
Date: Fri,  1 Jul 2022 17:16:19 +0800
Message-Id: <20220701091621.3022368-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v5 1/2] mm: Add PAGE_ALIGN_DOWN macro
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: David Gow <davidgow@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, linux-mm@kvack.org, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ziw2qAXA;       spf=pass
 (google.com: domain of 3aru-yggkcfcczuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3aru-YggKCfccZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

This is just the same as PAGE_ALIGN(), but rounds the address down, not
up.

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Acked-by: Andrew Morton <akpm@linux-foundation.org>
---
Please take this patch as part of the UML tree, along with patch #2,
thanks!

No changes to this patch since v4:
https://lore.kernel.org/lkml/20220630080834.2742777-1-davidgow@google.com/

No changes to this patch since v3 (just a minor issue with patch #2):
https://lore.kernel.org/lkml/20220630074757.2739000-1-davidgow@google.com/

Changes since v2:
https://lore.kernel.org/lkml/20220527185600.1236769-1-davidgow@google.com/
- Add Andrew's Acked-by tag.

v2 was the first version of this patch (it having been introduced as
part of v2 of the UML/KASAN series).

There are almost certainly lots of places where this macro should be
used: just look for ALIGN_DOWN(..., PAGE_SIZE). I haven't gone through
to try to replace them all.

---
 include/linux/mm.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 9f44254af8ce..9abe5975ad11 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -221,6 +221,9 @@ int overcommit_policy_handler(struct ctl_table *, int, void *, size_t *,
 /* to align the pointer to the (next) page boundary */
 #define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
 
+/* to align the pointer to the (prev) page boundary */
+#define PAGE_ALIGN_DOWN(addr) ALIGN_DOWN(addr, PAGE_SIZE)
+
 /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
 #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701091621.3022368-1-davidgow%40google.com.
