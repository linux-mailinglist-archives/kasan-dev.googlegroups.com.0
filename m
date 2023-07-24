Return-Path: <kasan-dev+bncBCSLFNNRQ4LRB7W57KSQMGQEVLQU3NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D24075FCDD
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 19:04:00 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-993d41cbc31sf376220166b.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 10:04:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690218240; cv=pass;
        d=google.com; s=arc-20160816;
        b=RNSOZzCsK1OTyjqKRchtmsp2r5rprUoQGkpNQNWeHRc4TsPe+z3i0h2Kf9aHAYbH9P
         Sfygc3iSAHrqZXyTsy5vArdzepGJOCuJWDHxehQqgaJm9qdvyea/7wzd4bU3KqjvnGSp
         ygS/z7dIJq91bQFWIPmTIU2A6SHL7zBDWiAdoLmrZxTvYtUab9F1ZqJcnSRvhZVVhzaU
         cqUCcNXoX0VCS4QZ9QVIJUiFB2YcKQ71iodbjtgonJm9uPmVgOAPy+5DZcUHXigmQ84d
         MozJLo+/lnq2zhwWwmIUbCp9quLKdePvEL5YnttynHkxFAO0kUrsm3tz1EbaNf0FpFWW
         hA5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SJLSqDJZRhknP9AhbUy+UOH6d/g2lEJjFn00TVQ6aUU=;
        fh=8QOdoXAkdgM3kVmr53MK5lC0RpM8fsLltxTwScERO7w=;
        b=sKvFvVAdFuDoR/K3RrKm963sDvwKl2Yi75CaUkhk5gfoRV6W5Vj4jqHoVETyfzV0Qi
         MUs775y0/EWU876c+MgeXxDVvW6EcCSr9Rw215ChR07KicvgNq7cG75rbxXaOBPWzlGM
         YvVgT+wS9FwDEQeNirB7E4pYWo2HkIYvzcIzyPQH8cN/pawckuoTo2exD+Sgu0kv83M7
         moDRCLzDptLCvQ3XHim8BTqEMP+dLimlJnFcIqYiv0vFJG9kxzAwCUJrStwbAVDh0qKj
         4J1mTKY3DLRshw7FQ87CJM5ToW4KQneEht5TiBTy6GPczgXgJAzlfGCntX2+Pg7WmlrD
         6djg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 2a02:1800:120:4::f00:14 is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690218240; x=1690823040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SJLSqDJZRhknP9AhbUy+UOH6d/g2lEJjFn00TVQ6aUU=;
        b=U0V6rBCsFstBoujfhFSBNHbmEKdoaJdU+X4dx9/ieFcHSFPanxGPfC1Pq9BVDz12Yh
         KWc1sZ0C/c7j4fduCnG/RDBKC5cBaNFCE2SqTvQRk6i14WurjkHR+w3OpgBx++lrEC5t
         KRoxH2QLvznLWG2+MJl/ZyKgkxd4t0bnEHnxWOGEl5UBLhj6YFSE6YXG53trbWMKOlcg
         IsCfxi7V01K9rgUJGHilpTDn1/ZB/54p67l1UX/EJazOzUPEdy7ctESrBhDQqpukb57e
         ntbNmkM/bS32Rgw7qW8tfs0FMDu/h2TskfTF/l4Ig4OOF/AayknR6GgVSqSPL3cKykGL
         02/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690218240; x=1690823040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SJLSqDJZRhknP9AhbUy+UOH6d/g2lEJjFn00TVQ6aUU=;
        b=L6L7A3FJRDM6qafUhhdKwQca0TD7hd9Gx6XK+Nrs9/whiQh1vEmsd4ciN7VpLsWHqI
         RkhRRTnFyveweU+0IXDNJL20H+jF8I5YMSNH9PMuGUOWezMSB1GRg6uFoi2wZm+b3l8d
         DIznzdpO2qSDMS4nNXM3Sls9V1e6XjMiE9QBzYL0Ml3KbUC5p5Lwf4LsqIQIE+6zBEBS
         n/VbY/R05ny9eBVe7IGcpLObXib78u4F+rnosAW+iLpvqmkiZRIZjAMmH3ppEQqJeHJi
         MAVJhwhLA1NOq+ksIfaJy1CklBLsMG+ykDZr57cXQAyejPX6UTqxtIu3VfCbi5qtPQxM
         96BQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaoYuwO/+6cpIgNuL8ufJUqS7icDZvfqSdsO8o3890Cb2xsPXZF
	xOE4N6gogqZuoTXO2oTK82c=
X-Google-Smtp-Source: APBJJlE0pmAnL5WcqaPHwygQ6XpqDw0byG9hPNdAKSXzXOslPf550qBWH4KMKwsDYDycdD+hAE2O1A==
X-Received: by 2002:a05:6402:b06:b0:521:8a13:644a with SMTP id bm6-20020a0564020b0600b005218a13644amr9469304edb.23.1690218239187;
        Mon, 24 Jul 2023 10:03:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cb54:0:b0:522:41b8:fcfe with SMTP id w20-20020aa7cb54000000b0052241b8fcfels62530edt.2.-pod-prod-01-eu;
 Mon, 24 Jul 2023 10:03:57 -0700 (PDT)
X-Received: by 2002:aa7:ce0b:0:b0:522:2711:873 with SMTP id d11-20020aa7ce0b000000b0052227110873mr4652989edv.1.1690218236994;
        Mon, 24 Jul 2023 10:03:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690218236; cv=none;
        d=google.com; s=arc-20160816;
        b=COK+QhT68BAVwY5ngs+FobziG8JUOZbu2UOWWb5IPrtFKE7mXVKmELwabyMiQGktpy
         y+Y8DSU/1v5bLh2QN5EGimoBmWwCN6kGktHs3AmpWAWrw8lTOAYRencT2i6TOxjTMGus
         A6tafMcbjG2P51g890F+DngGFBq7RJpe7FxvMgqGhts4S1nmAzhKX/v9Dsb/00Pxf8iz
         uEgwwICWS4DRITrFA1CAjBN2Sv8Udyuu7RdBghyAhknDnV3AqM0019xvcrkJCxD3dBAN
         f7YnAUSOLwdEKnY7hgJlnSwbJ8uUyXXuchH/nVvEnRZ2vLyx460vphcaiY4hypeuvMeE
         bjXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=7nNlqh/M1sJij1FcLOZzUS65T2Uv+bbbr2phi4BKTQI=;
        fh=8QOdoXAkdgM3kVmr53MK5lC0RpM8fsLltxTwScERO7w=;
        b=Y9Lj3xJl1HcAQif6fmAXsTJ1oUrD4jkoX+7QZ/ZW+2ZM/l52iNr9nwG+zqiw4el7H6
         0iJhWHPyMVw9vt6iOCaeCsy93IdvtfBa7DGBd0TL4gAPehYOZlVmIBnqAJNJ03QAheNS
         VnuSKU2YxPX56rTaMQjQdPzwNctWkTrT48jMjGP23eVX0Xzd2U86gf18g7Q4uBLX5UIJ
         blbW9pvMpDcdJa/+QoLJtne8guYbMHSTlQvtY0gWOq11O7vGT6LOoopeiPQiBnFGZcpS
         aYMdkWElS8d8fSCgibQ4XKwwyjaUyqsbMhS9NGDxJTnNZQPGtMr0rP5TB8yIWFZ22Vbr
         DcVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 2a02:1800:120:4::f00:14 is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
Received: from xavier.telenet-ops.be (xavier.telenet-ops.be. [2a02:1800:120:4::f00:14])
        by gmr-mx.google.com with ESMTPS id g20-20020a056402321400b0051e6316130dsi552894eda.5.2023.07.24.10.03.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jul 2023 10:03:56 -0700 (PDT)
Received-SPF: neutral (google.com: 2a02:1800:120:4::f00:14 is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) client-ip=2a02:1800:120:4::f00:14;
Received: from ramsan.of.borg ([IPv6:2a02:1810:ac12:ed40:2d50:2ea4:d4e1:2af3])
	by xavier.telenet-ops.be with bizsmtp
	id R53t2A00F2TBYXr0153tLe; Mon, 24 Jul 2023 19:03:56 +0200
Received: from rox.of.borg ([192.168.97.57])
	by ramsan.of.borg with esmtp (Exim 4.95)
	(envelope-from <geert@linux-m68k.org>)
	id 1qNyyD-002PJX-Ku;
	Mon, 24 Jul 2023 19:03:53 +0200
Received: from geert by rox.of.borg with local (Exim 4.95)
	(envelope-from <geert@linux-m68k.org>)
	id 1qNyyP-007DmR-NR;
	Mon, 24 Jul 2023 19:03:53 +0200
From: Geert Uytterhoeven <geert+renesas@glider.be>
To: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
	Daniel Vetter <daniel@ffwll.ch>,
	Helge Deller <deller@gmx.de>
Cc: Kees Cook <keescook@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-fbdev@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	linux-kernel@vger.kernel.org,
	Geert Uytterhoeven <geert+renesas@glider.be>
Subject: [PATCH] Revert "fbcon: Use kzalloc() in fbcon_prepare_logo()"
Date: Mon, 24 Jul 2023 19:03:48 +0200
Message-Id: <98b79fbdde69a4a203096eb9c8801045c5a055fb.1690218016.git.geert+renesas@glider.be>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: geert+renesas@glider.be
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 2a02:1800:120:4::f00:14 is neither permitted nor denied by best
 guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
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

This reverts commit a6a00d7e8ffd78d1cdb7a43f1278f081038c638f.

The syzbot report turned out to be a false possitive, caused by a KMSAN
problem.  Indeed, after allocating the buffer, it is fully initialized
using scr_memsetw().  Hence there is no point in allocating zeroed
memory, while this does incur some overhead.

Closes: https://lore.kernel.org/r/CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com/
Signed-off-by: Geert Uytterhoeven <geert+renesas@glider.be>
---
 drivers/video/fbdev/core/fbcon.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/video/fbdev/core/fbcon.c b/drivers/video/fbdev/core/fbcon.c
index 8e76bc246b3871b0..0246948f3c81a7a6 100644
--- a/drivers/video/fbdev/core/fbcon.c
+++ b/drivers/video/fbdev/core/fbcon.c
@@ -577,7 +577,7 @@ static void fbcon_prepare_logo(struct vc_data *vc, struct fb_info *info,
 		if (scr_readw(r) != vc->vc_video_erase_char)
 			break;
 	if (r != q && new_rows >= rows + logo_lines) {
-		save = kzalloc(array3_size(logo_lines, new_cols, 2),
+		save = kmalloc(array3_size(logo_lines, new_cols, 2),
 			       GFP_KERNEL);
 		if (save) {
 			int i = min(cols, new_cols);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/98b79fbdde69a4a203096eb9c8801045c5a055fb.1690218016.git.geert%2Brenesas%40glider.be.
