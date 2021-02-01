Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH6N4CAAMGQETCTB4CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A46A830AC37
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 17:04:48 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id h18sf6423641ljg.14
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 08:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612195488; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIhN4mYPpAP/kvC3AZGsxOiFOzx8Gew9FmD6bPt07xIguaegB7Ftu4cnRZlr9tKtyZ
         IJXG3mRV8AzOdk8tgWfXV/mLLMsgD3objmskWegsRQeKZ1aGl4WMqDCdH5sozApysj1W
         nTy8Ex8CHqlf0/JAa6HVnAhBw+al5qEXlf9EMDohtgbmtxNqqweYUXEoQF9I92G1qAQD
         a2N4A3hucwd/JV7G7Oi1h6LJLyQ1ZygWZog0++nOzwOnCxQoNvMHXpBhXimZw6+nV/TS
         LNhn1zKn+xLWmB9cDiv9oW0MGhTme7WceeDR2ubvZu5PUahNGNxC/dwRmLs6Nhoca0Hv
         rXTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=eBKu5Nk1mXWSqvXI1lJXXxgXv/JvYYymTHDsVaFxrCk=;
        b=b61VjoMMNl21n+ehRSQOUqOPU5xvfzMLVf3uqKzwET+W69Es/SoM5wYMzsFQoRpijX
         Kxg8HiMs1u5ELbexs0NKyGXxS2wgcEAAqg6JsjshCyaW4VQctYXv8h0+CK9A+QF+kRjL
         zsjoDggu0TQyz0UWYHG3RP8XPV1qCL3jXIXiVnHu647Bt6J8wrdTEmGwSaYJtY+3IVO+
         KF0kUd5AEhCLJdIipueEaUlNh1qxo0mqeMqTPnVn3JzFv5T4QkYPSsjM0BlGdJYJySTx
         8PQ3UA9tqb6koBkisEqRT1U3OATS4AdPzGl4T65Nc6YfXpNLBosOO0nTrLbvjihlWC3G
         NMNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NepNoYaS;
       spf=pass (google.com: domain of 3nsyyyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nSYYYAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eBKu5Nk1mXWSqvXI1lJXXxgXv/JvYYymTHDsVaFxrCk=;
        b=Nngt0RQr+C0oqBWhZ99r2rlqxPpwurGYwXhZ51gucBVnGXoJvl6U5+JFccsTUgDYQH
         aTdamXzeFgNnvyIwVagbLPrUc7cgwSbht0JMNbuxkO79Hnd5KpKG39AjLgY7UZpQW62S
         2RNO5RHWiLF1sQjASbD1noYxN9791HbSkNS+rJxPGtstVhTqmGYm55iD1k+A8cxRJ2JJ
         H8VA1PKXe9TwoOnSDR/SxCRJlklF/M9MELzfqFDG5XWpj4L/pgC1LPsHfA923Sli0AAf
         jipH+WPGO0U52rRkFeMMPQdtf2YI16c8liz0g+7J9cCIrKenMQ5W03Hj3P6BKdXQlB15
         YXRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eBKu5Nk1mXWSqvXI1lJXXxgXv/JvYYymTHDsVaFxrCk=;
        b=o1CU0Myz6huYEaP5ojwsldnx+8iQApHVF0BiUonrPWzEeb+1aS5aX7bRkgIFDc2phx
         XV9FVl0FdQnzYQik1At8mWp3wi63HbX1E9w93/phy2q7/Yi1BhZrshKbClPcOK/6iWoc
         wacOd3I0oQWG2Fm3iD2rq00XVfV5AYjd8Cx5ZdFK32x9Ms5jyX4GMt7r+Dv+sAgAfk9/
         q3TpGM3Up5VQo6efijvlDr4FFItHCf6dz3p8bDIUDKukYntxeltygEhsHB/9z99BDxRi
         94PmkSP9/pvyNB3ePOHY9hY4G0zoETpILll2TQmkqgLmeFehdpNqgWqbK7YqHyB1+vkN
         Tizg==
X-Gm-Message-State: AOAM531nxkbxUBt+8217morYKpzm6RK5eMbWqeSyaLl2blq4HASy0i+h
	RqRLlzL1TWNhym/Yppu+DFk=
X-Google-Smtp-Source: ABdhPJzFp4Dpuen4+iwj+YRycL2p4mqYIrt7F5RfWjdt/77XlPZv4JH2fNw3MX4+BmO7ysSos9iBcg==
X-Received: by 2002:ac2:548e:: with SMTP id t14mr9158342lfk.290.1612195487748;
        Mon, 01 Feb 2021 08:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5519:: with SMTP id j25ls1054240lfk.2.gmail; Mon, 01 Feb
 2021 08:04:46 -0800 (PST)
X-Received: by 2002:a19:488c:: with SMTP id v134mr8619326lfa.229.1612195486322;
        Mon, 01 Feb 2021 08:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612195486; cv=none;
        d=google.com; s=arc-20160816;
        b=pZ4y/YpMMN6V3izA0MnjK9zi41ijgDsQ1gdq/sfvgQIWdPF15nnpMebyyJq7ftOvom
         xWZRiI4GXs62oUWJLo3zYErqiJYJpoiDlsJMjVLJrZ6UoeHCg+rlq53KStvmgFOi7iJq
         7Cf0BhNdQnDlrFysIthZQHZEGpgUy4TytjzZmKy8bO9raCluXffwrQXTeQQ84ZouIvCg
         LTgo159H8udNNMCQVchGtu8kyH7M5pONLaKXDQuLZ8WAyAaFEV6cX6DaEoSUij8Ht3Kz
         AMVS0BsLjO6m0JkzcxFIvkwD2xfb01cZMvAIqdhPtyB191n4U10/B7kRrt4jyDO123oQ
         Rh5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=k0C1xWSejIoCUIkR3Xdpp2QfnBoYRRN5HyYkZB6dBTA=;
        b=xVpfaQVEhlU4DjRLz3I17cPovU+VScDZaHe8JKNjXr7Szkp4s5antKcVpije5nC0lt
         VKAYmvTVrPUfVL31ayWTld8/7QmkYTk23n1pKhW+2pRjcZM+Q0XOQqLDv3hDnjNHCYvi
         7MFx3Zlc651hn0Lx0DG+Bdn0hmMuKtmvGzWWAKmRCXpvoUh3OAVzddXBsUmPNgzseami
         wqCC8VQlpxkBv61vM19+2c0lTuwU4kFxHrRCv/TkmIzFlRm1WBxOZ17y7cfPz3iHHE1J
         R9JDq74rEH/o4r+Mj6XX/VlQ4HY5Fw8YZlGWfVYzAM6TMPcNO1/+/dagGoRFbA2Rr+FI
         yxfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NepNoYaS;
       spf=pass (google.com: domain of 3nsyyyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nSYYYAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id h13si843196lji.7.2021.02.01.08.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 08:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nsyyyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id p16so10266183wrx.10
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 08:04:45 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c76e:: with SMTP id x14mr2587288wmk.17.1612195485394;
 Mon, 01 Feb 2021 08:04:45 -0800 (PST)
Date: Mon,  1 Feb 2021 17:04:20 +0100
Message-Id: <20210201160420.2826895-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	davem@davemloft.net, kuba@kernel.org, jonathan.lemon@gmail.com, 
	willemb@google.com, linmiaohe@huawei.com, gnault@redhat.com, 
	dseok.yi@samsung.com, kyk.segfault@gmail.com, viro@zeniv.linux.org.uk, 
	netdev@vger.kernel.org, glider@google.com, 
	syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com, 
	Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NepNoYaS;       spf=pass
 (google.com: domain of 3nsyyyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nSYYYAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Avoid the assumption that ksize(kmalloc(S)) == ksize(kmalloc(S)): when
cloning an skb, save and restore truesize after pskb_expand_head(). This
can occur if the allocator decides to service an allocation of the same
size differently (e.g. use a different size class, or pass the
allocation on to KFENCE).

Because truesize is used for bookkeeping (such as sk_wmem_queued), a
modified truesize of a cloned skb may result in corrupt bookkeeping and
relevant warnings (such as in sk_stream_kill_queues()).

Link: https://lkml.kernel.org/r/X9JR/J6dMMOy1obu@elver.google.com
Reported-by: syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com
Suggested-by: Eric Dumazet <edumazet@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 net/core/skbuff.c | 14 +++++++++++++-
 1 file changed, 13 insertions(+), 1 deletion(-)

diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 2af12f7e170c..3787093239f5 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -3289,7 +3289,19 @@ EXPORT_SYMBOL(skb_split);
  */
 static int skb_prepare_for_shift(struct sk_buff *skb)
 {
-	return skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
+	int ret = 0;
+
+	if (skb_cloned(skb)) {
+		/* Save and restore truesize: pskb_expand_head() may reallocate
+		 * memory where ksize(kmalloc(S)) != ksize(kmalloc(S)), but we
+		 * cannot change truesize at this point.
+		 */
+		unsigned int save_truesize = skb->truesize;
+
+		ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
+		skb->truesize = save_truesize;
+	}
+	return ret;
 }
 
 /**

base-commit: 14e8e0f6008865d823a8184a276702a6c3cbef3d
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210201160420.2826895-1-elver%40google.com.
