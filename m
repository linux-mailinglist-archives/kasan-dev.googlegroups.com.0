Return-Path: <kasan-dev+bncBAABBHXGT34QKGQERDKBTEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id E3DC5239FC0
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Aug 2020 08:47:59 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id q7sf22485948qtd.1
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Aug 2020 23:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596437279; cv=pass;
        d=google.com; s=arc-20160816;
        b=GWmgXa/gt3G4vPs/IKcHTxI04FzvRQGnuZcZyH9faGfoWFKXgOTdyq9wooc30Gwu1j
         eGapX8LvBtQ1oznfSGfkSLIM3l0lU8U6lE5k2nztvvORKwEqukAPxsxKDrlNK5nrCCCG
         WWcIxukBvxPcqZbUY6FmVUdyQecFPuJ3INdDDoWZcy7eFFUfmOLa3ecKgWYPCJI1baVh
         jQcY5BX4km7p3MdCDDTNFPhm1nHdJ2dYAytSWtGnIQ3lN7VH7mwKBa7dFUOLXYc8DLzO
         CQZlm+LCwdtfIyw4SosCyt8e1JPRoaD0aoD0WhRL47f+5EuJAvcM+ih03JUtPcaKSYO4
         wJ0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=GLJjFyPm7iAPVapZf+QO6GHrFhAFSvV+xOQyKtASKEs=;
        b=HUKIaJrVYxHZ3QOJO9tdssNCZm2LSDJgd4cfggU/qYkLbGpxRKqn7DqgnNNBzgUIJp
         7bvZvXV7EbBTPvojhprSAoX+6yNZvQ3HUPEI9HqmrENCNCHeijmBNLnDoJaZQNZqs6Zu
         FpqZOOIoefHw50Wttvz0YoUn3TSZNtS1XNw4PpFIOkrvoUChlyzfxJyp1A8tRp5TCa/F
         ajhQQc8DSIgDOz/BrnCCnJzWXnm9qjPiabTMcgiCipesEhJrlk54xackekCHnBlU4zYq
         rstrV9wR0bNS7Yt2hO7iVIvtGVxwtEeVmrsfhKjwFZJSWwGhBR1k0PypHdsZWE1WhMem
         ZbUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wenhu.wang@vivo.com designates 103.129.252.23 as permitted sender) smtp.mailfrom=wenhu.wang@vivo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GLJjFyPm7iAPVapZf+QO6GHrFhAFSvV+xOQyKtASKEs=;
        b=gchRqzA/GAZVdW+M2AurbzRdtHe4ys91T4M2GMoQusK0Q1CfrW+dc13zCPeXy0rHR3
         L9wfQSuOghrzrW4HTye0h67i5Uuk1QkbDHwLdUK6QvjT9uWm0gkGgxvDdaTzbVAHlXlT
         4EJWB038OWygc1qHUSadH+Hwuh6EYpoVxwwkSKmN/RyEwbeH3U4/gDjdap9JkiY+KQ8V
         bjxLxBKBmACnJ+Gp28qg3nEGRBcMV9Rg4fOgSCAsmwdhoJy3AliNTYxhcNrVirI/J148
         VSfFcLykjHQxjZP613Mr/0fVRIfuH3tz+wat9fpA4Edcp7n7nDpxG1UABHyePKqpyakd
         /0tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GLJjFyPm7iAPVapZf+QO6GHrFhAFSvV+xOQyKtASKEs=;
        b=AgCKyvor1LezrB3uAymdPgklSpcr7P2KXYjiv31lrlz+4tcsafJhSu34kmZkQshy95
         7qzZtimTji2s+hoHuuPu1h+xqBu+QqmcuVdJe0vbmKPrxLrejQDdCGXjTcuKZjJh5czo
         4N9FaU/8lgbwA0cblx4PqL38MzO3asAxTjFIR2cdzzxvK0q7mrorwDL4fxplYSYux7ax
         SSzW4QDrOZralwcaiJP+sA3R4LPABHJCGLA4WQZW9PIkbInmXWLSgs1uEh3WerXPuFJz
         yQ64Pe+877Zq5hz5TpqhqWmVe/fVCv31NDqEz3apwQfkY2x/a1fOo/eKatOm3DVjUKtM
         nrBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303Cmk3c6TppIlKsfUS17UALaSyFVi7XYRo7/5XgPQYRdwDJakW
	91fQXLIJlBP/R6iNfYGftNA=
X-Google-Smtp-Source: ABdhPJy2dQQKmTuXU18qrUHic9TmMpCh/e3xCXAygqUO/UPB3kE3qApCQ1E/dyhuK+3gReGt0gX+EA==
X-Received: by 2002:a05:620a:789:: with SMTP id 9mr14451843qka.199.1596437278949;
        Sun, 02 Aug 2020 23:47:58 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:7d2:: with SMTP id bb18ls3776299qvb.6.gmail; Sun,
 02 Aug 2020 23:47:58 -0700 (PDT)
X-Received: by 2002:ad4:49a1:: with SMTP id u1mr15141281qvx.245.1596437278332;
        Sun, 02 Aug 2020 23:47:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596437278; cv=none;
        d=google.com; s=arc-20160816;
        b=gLTrAmFlafk1DgamnqQPEBLLJkmPE2IZnPWRfqgXHKkZ4FyujiEmy+/QE5z3K3jsPV
         8Fiw2XbCxEh9IeO7XSnPvo0Rzds68h92Bgw8Q+Ei6Upb0rwoZOY+R+nYvZU1bfzaloFy
         4VYkxb9ThzbqtNv6zv2DGJJvoXOKhqv9WWQ5XEXnilBSN6b7XNlpYJyZxTfNpACAmcBN
         7ZHkhciavvnUXvfQc/Kutziny0QrWV5C+jm6nySUKlECHRTGwlebWOWlZksuoREIqceZ
         WB2Sqqbayh/cWrAZHVpR1mpENlIthAnWfBpVzSPzFaj8t+S/83W/WdUrdXLc568aNyTh
         ITIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=YsOUs1nuiWDcyrMgW/htuREcmf3p+5QnFvAu2GQ/Nac=;
        b=Sfbs3D1CPQjYBUOsWW1AiO1U8q6s3ITDmQq5hAE9q815fip9d/VbuK+Ul5XwbocnKI
         BS6TweHZgfcUa5E/ofK5Ga2KA1BbGZjaRypExDEIwnUQRmjcySfwNXDW3Ta79ga/Y7ya
         LaiAGfmNpSbcet8oNI9l+ZrIRsJqSn7qoZmiA8MkFjNmtpyEaH9/Lpi7S8msB4nCLWdK
         lnpdekYKB0TMdniP8UdGCGEQywT2SxmoVbNzwoM29mNDfh4+KGDs5Wkd2+Pbz0RvYL9N
         XgMElTvLaO7EK+N9wkKzdWu4xYT10povTfidMxElT3g46vrzRob7CsehNq8rZnP0yvZk
         7ixw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wenhu.wang@vivo.com designates 103.129.252.23 as permitted sender) smtp.mailfrom=wenhu.wang@vivo.com
Received: from mail-proxy25224.qiye.163.com (mail-proxy25223.qiye.163.com. [103.129.252.23])
        by gmr-mx.google.com with ESMTPS id o2si768273qkj.4.2020.08.02.23.47.58
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 02 Aug 2020 23:47:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of wenhu.wang@vivo.com designates 103.129.252.23 as permitted sender) client-ip=103.129.252.23;
Received: from wwh-vos.localdomain (unknown [58.251.74.226])
	by m17616.mail.qiye.163.com (Hmail) with ESMTPA id AB959108499;
	Mon,  3 Aug 2020 14:45:48 +0800 (CST)
From: Wang Wenhu <wenhu.wang@vivo.com>
To: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Cc: Wang Wenhu <wenhu.wang@vivo.com>
Subject: [PATCH] doc: kcsan: add support info of gcc for kcsan
Date: Mon,  3 Aug 2020 14:45:12 +0800
Message-Id: <20200803064512.85589-1-wenhu.wang@vivo.com>
X-Mailer: git-send-email 2.17.1
X-HM-Spam-Status: e1kfGhgUHx5ZQUpXWQgYFAkeWUFZS1VLWVdZKFlBSE83V1ktWUFJV1kPCR
	oVCBIfWUFZGkJPSB4dHUlITB5CVkpOQk1PSExKT0JLQkpVEwETFhoSFyQUDg9ZV1kWGg8SFR0UWU
	FZT0tIVUpKS09ISFVKS0tZBg++
X-HM-Sender-Digest: e1kMHhlZQR0aFwgeV1kSHx4VD1lBWUc6PFE6FRw4Cz8eDwEjIQMxCT4T
	Dx5PC01VSlVKTkJNT0hMSk9CTU5JVTMWGhIXVQweFRMOVQwaFRw7DRINFFUYFBZFWVdZEgtZQVlO
	Q1VJTkpVTE9VSUlNWVdZCAFZQUpMQ0s3Bg++
X-HM-Tid: 0a73b311b53f9374kuwsab959108499
X-Original-Sender: wenhu.wang@vivo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wenhu.wang@vivo.com designates 103.129.252.23 as
 permitted sender) smtp.mailfrom=wenhu.wang@vivo.com
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

KCSAN is also supported in GCC version 7.3.0 or later.
For Clang, the supported versions are 7.0.0 and later.

Signed-off-by: Wang Wenhu <wenhu.wang@vivo.com>
---
 Documentation/dev-tools/kcsan.rst | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index b38379f06194..05a4578839cf 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -8,7 +8,8 @@ approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 Usage
 -----
 
-KCSAN requires Clang version 11 or later.
+KCSAN is supported in both GCC and Clang. With GCC it requires version 7.3.0
+or later. With Clang it requires version 7.0.0 or later.
 
 To enable KCSAN configure the kernel with::
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200803064512.85589-1-wenhu.wang%40vivo.com.
