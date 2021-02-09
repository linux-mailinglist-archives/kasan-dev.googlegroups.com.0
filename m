Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD7DRGAQMGQEGS3PVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C5F0314E2F
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 12:27:12 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id y9sf2096684wmj.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 03:27:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612870032; cv=pass;
        d=google.com; s=arc-20160816;
        b=z+vG5o8zholURwNFPJlFJMjbmwcWECfBainX6QZcxjP2zuHtoZINLKb5RtfVshq/lB
         gtuh1fBURiYb6T675QlscfVRjdRBaEf7y02l1ffwPOFEPNRkMBB1J+DXSn7pDT9y+vA0
         Kr5oJi/BWwgeoVOHOUusCZYpg10bwJYZqDLn5dt6RPZWt36XOv7BSKnEq5WrnGMhNws0
         gPL+uqc7YGFipLl8Arau/t+o8uNlkiiO1EzVmMoE5QEE5iweRY4iKrwE8kGkvWhsebNj
         CcsGwCf7z7FBV94qTtGE8o+t+S+JMsSNxGYy2MESTNNIWfP+W8903r2mZtOAN0fCz9t/
         QYXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=jKmWuLRUcB850wOoDoWOTtzk1k411bs0J+vcQC94yCQ=;
        b=kjj+8AFPTtfdIF+LrBcoq1lwfnHaQDklpIyz3OSiWCAjcGxnX3kk4+XhiDdJwylQit
         tbWsmqsC/IzuohuuMN15yot6kYDL28weSIEPe64dWOwMhn555aVUqf4PivyIcfSWaYv6
         mJPbmo7EyPU32UEFWwsArL154bN3p8V86w4DvZ3xosJRHELuIiPsuBklETfLFGjcT/uT
         NXLNri+D/5L1hQKQfWSVLgbYPcFjH5ZkQ4iuq0i5KmISHG8q/27FIsg4yX5VT2fBAAlx
         0FTh5Kf3b7kcxS8wt4sjzhnFafkURq3EbD91KozOu5xKypnGw1/1RZDycL9VSuSGSS+V
         lXEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ofP339Bc;
       spf=pass (google.com: domain of 3jxeiyaukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jXEiYAUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jKmWuLRUcB850wOoDoWOTtzk1k411bs0J+vcQC94yCQ=;
        b=N8JIB9yNoMKIlAqhABwxSl2hEnXq//btryjIjkuyx9hGswDpe1DyE6Vp34Xwx10bav
         1ymgNTAzrGfFBU43BupnFIajn3U8HaiXO4iFN717c1rjCOCmiJnpFoWTaBlG3e1BasiK
         9Gu2lPCSi8Apwy/JLFvR4erPPrVr/gXsS1W+CZLKNWANaPcp4MTh3XVIxjgZkPgIbjVb
         woVQDA1PgdAFDi5TCk7WPRCkjAzyTygNVrxAoVZr7oUFo8UrDrIkA9FkKZ2WAsBbTEmQ
         uFaanWHXqQjE7WCxbg9JaSIP9CQc90ET3lfo03XbbBlw2zlCExjaDEaYf0qpnPvThkig
         j9AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jKmWuLRUcB850wOoDoWOTtzk1k411bs0J+vcQC94yCQ=;
        b=UUou8niXV2uNUOcJuHS5JmmCOvF8ceILgUgxtJvbZdZnG6Pqf4XsbACMg6MyTu8lrh
         ZvOY5DKUCbKsUJhOZJQZgSe+vQABBpEvF8NQWoid+R0qWrji8PrHC0iasOmtkUeMoHry
         dA1VEYHAVWRrL6kHiXMG6Ktzk1fBM8HEJY3FCpfFFJvOC1EwzHK0NZLoETQJDOK6N0IB
         4sTKEwoMapvYm1jxlCzxgdnt7pVHFp+gP02bTJoFKEpDl+5/8ORtuio4Rx9OTrWeqSmP
         875NbHzhUrkACpb8iDT+w0G2EgeyD9ogYf0Z3QSe7eChmTtRHeBhBGOr3v7ypY/DlGgN
         zLRA==
X-Gm-Message-State: AOAM532NScDaxmiPpU9eY8HZnCXLJ+cpssDuLzLuPz+9tdLVMn/G+ZJ9
	l/W7Us1EZEQN+BUmoLj+Tfo=
X-Google-Smtp-Source: ABdhPJxkhXUo2stZ9XpUCn9HofbKKU9pvyOoy0L4Fjjtc6f0BCMBObxaBukGfaLiVO92pL4ZWyZKRw==
X-Received: by 2002:a05:6000:188c:: with SMTP id a12mr25686762wri.105.1612870032030;
        Tue, 09 Feb 2021 03:27:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4485:: with SMTP id j5ls4121632wrq.1.gmail; Tue, 09 Feb
 2021 03:27:11 -0800 (PST)
X-Received: by 2002:adf:b60f:: with SMTP id f15mr25183419wre.83.1612870031204;
        Tue, 09 Feb 2021 03:27:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612870031; cv=none;
        d=google.com; s=arc-20160816;
        b=Rwu6+kWyVaCxopqPVpEGaeTUzohFrWdbEFvEOx+5W0TLkpaHlCS/Zw5OI5hqGUez58
         Uwqft2pQSGU/UbuxP14dM8C5IzuIvPH5yOvoTfKnJbpom76I2aPGRquevnZFFFWqTFEV
         XjnHos8nWEJOK6bfIszfMq9fEDMOU0TDrOQ3zSc57wFbfERekFlkyYos7y+RI6dF5DiJ
         VWYq/H9/WY59bhbCWhnku5z2BHXQ3osku3ZAk5GkQY0LC3FUhEZoeyCE20kLQG8B6A5G
         5Pj3QH/eaqe8mXBGR8df4AIb/qXA/a9TDWZCRrkIvAHoOQ2o+x9QKFpp2B+bTzZY+VCO
         nKAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=A5PjxBocm6GkKPxXcYzX2e1AeHxW0gP+W7kFc8REg2E=;
        b=oLG4zcKTUfnKr98SV2lTY60vOqavcJgQn/ahXxietkMcvRULHEOOfKGPojHCO9vpyB
         A8T/XcokqSu5JNuQRkRmwvhZENZvzL+/itdlkSHYkx0zP/vSlKk8SghhrHdrPYjmVd/u
         f8yr8DLjvBek+RAxIvoSHlR2Z5pregzPNbx1I9+L2Kqxx1nFRzbslG8x59bfjtQHeay+
         S6W82E6a3rD5fJg8PwOwoiw82F+3DinpM12l5x9wi7PSRkijomgPNh+3nTP75bc0Qyk5
         pJcCnKrx1wzOrddLf+If1tdrBzVf5CExR60Q2PRIPvlvYM/EfOecuaCRvTpupZgOA4UE
         3r0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ofP339Bc;
       spf=pass (google.com: domain of 3jxeiyaukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jXEiYAUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id u65si46352wme.1.2021.02.09.03.27.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 03:27:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jxeiyaukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id w11so9632878wrp.6
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 03:27:11 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:51c9:b9a4:3e29:2cd0])
 (user=elver job=sendgmr) by 2002:a05:600c:35c9:: with SMTP id
 r9mr396002wmq.0.1612870029964; Tue, 09 Feb 2021 03:27:09 -0800 (PST)
Date: Tue,  9 Feb 2021 12:27:01 +0100
Message-Id: <20210209112701.3341724-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH] bpf_lru_list: Read double-checked variable once without lock
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, ast@kernel.org, daniel@iogearbox.net, andrii@kernel.org, 
	kafai@fb.com, songliubraving@fb.com, yhs@fb.com, john.fastabend@gmail.com, 
	kpsingh@kernel.org, netdev@vger.kernel.org, bpf@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, paulmck@kernel.org, dvyukov@google.com, 
	syzbot+3536db46dfa58c573458@syzkaller.appspotmail.com, 
	syzbot+516acdb03d3e27d91bcd@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ofP339Bc;       spf=pass
 (google.com: domain of 3jxeiyaukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jXEiYAUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

For double-checked locking in bpf_common_lru_push_free(), node->type is
read outside the critical section and then re-checked under the lock.
However, concurrent writes to node->type result in data races.

For example, the following concurrent access was observed by KCSAN:

  write to 0xffff88801521bc22 of 1 bytes by task 10038 on cpu 1:
   __bpf_lru_node_move_in        kernel/bpf/bpf_lru_list.c:91
   __local_list_flush            kernel/bpf/bpf_lru_list.c:298
   ...
  read to 0xffff88801521bc22 of 1 bytes by task 10043 on cpu 0:
   bpf_common_lru_push_free      kernel/bpf/bpf_lru_list.c:507
   bpf_lru_push_free             kernel/bpf/bpf_lru_list.c:555
   ...

Fix the data races where node->type is read outside the critical section
(for double-checked locking) by marking the access with READ_ONCE() as
well as ensuring the variable is only accessed once.

Reported-by: syzbot+3536db46dfa58c573458@syzkaller.appspotmail.com
Reported-by: syzbot+516acdb03d3e27d91bcd@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
---
Detailed reports:
	https://groups.google.com/g/syzkaller-upstream-moderation/c/PwsoQ7bfi8k/m/NH9Ni2WxAQAJ
	https://groups.google.com/g/syzkaller-upstream-moderation/c/-fXQO9ehxSM/m/RmQEcI2oAQAJ
---
 kernel/bpf/bpf_lru_list.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/bpf_lru_list.c b/kernel/bpf/bpf_lru_list.c
index 1b6b9349cb85..d99e89f113c4 100644
--- a/kernel/bpf/bpf_lru_list.c
+++ b/kernel/bpf/bpf_lru_list.c
@@ -502,13 +502,14 @@ struct bpf_lru_node *bpf_lru_pop_free(struct bpf_lru *lru, u32 hash)
 static void bpf_common_lru_push_free(struct bpf_lru *lru,
 				     struct bpf_lru_node *node)
 {
+	u8 node_type = READ_ONCE(node->type);
 	unsigned long flags;
 
-	if (WARN_ON_ONCE(node->type == BPF_LRU_LIST_T_FREE) ||
-	    WARN_ON_ONCE(node->type == BPF_LRU_LOCAL_LIST_T_FREE))
+	if (WARN_ON_ONCE(node_type == BPF_LRU_LIST_T_FREE) ||
+	    WARN_ON_ONCE(node_type == BPF_LRU_LOCAL_LIST_T_FREE))
 		return;
 
-	if (node->type == BPF_LRU_LOCAL_LIST_T_PENDING) {
+	if (node_type == BPF_LRU_LOCAL_LIST_T_PENDING) {
 		struct bpf_lru_locallist *loc_l;
 
 		loc_l = per_cpu_ptr(lru->common_lru.local_list, node->cpu);
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209112701.3341724-1-elver%40google.com.
