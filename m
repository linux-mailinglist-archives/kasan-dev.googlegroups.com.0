Return-Path: <kasan-dev+bncBCSLFNNRQ4LRBOEQR2TAMGQEWBVJFTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A8D17668AE
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 11:19:54 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2b9ce397ef1sf6283641fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 02:19:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690535993; cv=pass;
        d=google.com; s=arc-20160816;
        b=ed+At+Gbimc1WZvpG2uypd2Py3YMK5wfKbvZNOK2IJ0e6dh/30Kojnsw2Jmg/KTu6E
         fdaw7YnhpO3AC/HlSIl6BDvt44nB4RClr1JD1tVhCHf4N6nERfEI9JIJ2xIFwP0XxFsw
         7vZwyq4DseKs2W5q86XNv2dM2004F5iLmpbpO8y2REc5S5sjKR79En+V8yhaUMsDv8X1
         rXy3Js8O0yREKMLb3x46BHQhvEdhlFgRnfysFlqqRALUVGop9t0+gE4Og4RMvYn4gYjx
         WtZxWP+v9+9sQ3Kxf3wgtIOh59BNUv0pwKZCKzjAuLukucJA84Q8FAPwpMHAveFi8xCe
         q4FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=qJJYOO3Hy4vMgxJzlUKwS9hDBK4FD0DSfSXz8U8JzXs=;
        fh=8QOdoXAkdgM3kVmr53MK5lC0RpM8fsLltxTwScERO7w=;
        b=JiSjUbaKeNXuD5NazMV4bdFIJZQqDxZuFEj9D9HRXSyleP/I0qSN/QYxA9XVqpC4wN
         NVbC5h/ZH5eS2j7BAbwi+n6nHCD6eF6+UgXGbelK0K+dyXRS7ZAkYxjZBbBcAaznVeZH
         RoeSruiY+UYwpsvpNlO/6voae6uJzWaoUXHIvFpCINN/BlSBUUrL9v6TnpVSO8bzcFuw
         SNoOymymhZH2N6hDEBqaJMX6qgzliDzCjfqIWtf4h1IOxiaQrkAGLqx1Eg5iRfAVshCN
         U8VVftvhYNOMZ8JC1CyfJ4iw3jUXs0Yv0BA42KRHvxAiSRO+4GljTfN69UC2pPDF7A2L
         DgIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 2a02:1800:120:4::f00:13 is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690535993; x=1691140793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qJJYOO3Hy4vMgxJzlUKwS9hDBK4FD0DSfSXz8U8JzXs=;
        b=H5aAhSoTiRYde6ywW2pvfKxnJDOtvx6e0VAsFwagqsOn3jEra3XdriR3pkMqMXUsnz
         hLytTus+eEnJESjI87p3c6W9HHjva9nBVOoo5T7ZqaABj961+g91Yl6sEoKPcZSiqp43
         HmEzeYGheXQSWE1es2d5ImMkiZE85YxT3MEYphfaGC45SwoQqG4qOTCjTdvFWNBFaU5r
         uD+DTrXgEckxI7X1ldTWnhdqFKj2/fhdDemKbSY0cuVsXJuvXWy2FwfX6ipf6Zc2gKee
         QJM1y9KqUprVRZR2eSh94dbnNiIBnW3QgFDGzOlkIh4zw69ZRfDFNltU6a5c6Uhc8DUQ
         gIQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690535993; x=1691140793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qJJYOO3Hy4vMgxJzlUKwS9hDBK4FD0DSfSXz8U8JzXs=;
        b=lngB0YhD1XFSsZJwOujT4wWlOI2IVDKVsNZPIPmB7RWJ65jXXpUePMrq4WdPH8DeGd
         12VZNFCDH/TbnhqP5g+40yd0St4AgYpG2foNFL6wk+uj/NVKbzaj04kwYMMpY2eFJgvc
         8CYDHdLjd64SxR46ZbDq67tgG4OkXVnd1n9keiPwTqoz/bN+2bPzZ9HsZ8IVFOg6sCAg
         I4+P15qX2F0SMHyC3S4chcFmhEl5Gqjz6RVMyAKDQhJ5+FNemKfRDplGxBch0zKDDmFH
         k+iaLfutWyCS/w/hoeDK4L/E7LKRava+fKHQfplq4fHYwcjrKaP2QgSbH5841ITAZ65H
         rTEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZN1h2x6WqOk9bEUsp1SsGGb/x1Wu9DoazZen9rTZH1j2X/fOjm
	ytCEpengmJR8LlhkVaGV3wg=
X-Google-Smtp-Source: APBJJlFsv5UtB27woXgRfj9hOl+8qQxtClZ/JFV016i5kxN9EI8jvSzaM+wvBpLAxcGmGelGp9lfjA==
X-Received: by 2002:a05:6512:3d1b:b0:4fd:d6ba:73c2 with SMTP id d27-20020a0565123d1b00b004fdd6ba73c2mr1669157lfv.54.1690535992568;
        Fri, 28 Jul 2023 02:19:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5bdd:0:b0:4fe:678:6a1f with SMTP id u29-20020ac25bdd000000b004fe06786a1fls77431lfn.1.-pod-prod-06-eu;
 Fri, 28 Jul 2023 02:19:50 -0700 (PDT)
X-Received: by 2002:ac2:57c4:0:b0:4fb:cc99:4e90 with SMTP id k4-20020ac257c4000000b004fbcc994e90mr1006337lfo.37.1690535990189;
        Fri, 28 Jul 2023 02:19:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690535990; cv=none;
        d=google.com; s=arc-20160816;
        b=EwDizrmx2MAB1F5ixfNtzJMxT7vF6kFeD4ctGivG4cTSEg66l0/9Gzr+ltZtW93gt0
         3D2B2RPzQmmwDBvblTupEwPeiPdG2JC1ml6H65n32cmegvVGUO+ho5FWdyhTBN+P7sK7
         iQfE1wBcUBQ0iq0pgKLHQ9xYMK722DJTeo9ZyF83XRN61+WDq7uqeQqbXMFptHk8wGrK
         3/AmcDstNXEx54o0oFs5H0C4taWvQn8q+RXHH0dmPsWEQjJCk7DgjOHQIoI/W2bE7cQ8
         fDcHdWCNWX96FusvangKnWeRmJHCnFE0toBGJEmJlQlxMhBbTdMDB7IlYoWMzdCXWqjG
         ILMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=vj8xo2Q8HuQ0aIb6wvPrsig7eZ6sKhYUqfz+TQyYCYk=;
        fh=8QOdoXAkdgM3kVmr53MK5lC0RpM8fsLltxTwScERO7w=;
        b=x999AupRGF9gojY2lwdmXUdwrUALdnSB5odYcDKtMwFx6/Q0J/HM/CwjOq3oPwnAEu
         3aa0lluiPYk0Bb5zIvStN+9AATa2CWSz+dUQAy9+qUPluyAgc8eIivqPUKW7wxVmQhBI
         /a+fp0kjSwwv1ybB9RUh8mGGksBjSQ98PgRlOQLbj2bglamamS1VE0/X+lU/P9M5nhdY
         1NktpJedHA+s0jgxPH4Mo086bI6gBTMVlIiTyg7iPIDoO0UVB6+Rh7jFYHbV4QFE4Qq5
         vct5d8pAaWC00RBCivy1X0OI4DqY3125bwe/0gc56N2Bg5lFjk+c0uX7jAeZR+5vYPXa
         rsjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 2a02:1800:120:4::f00:13 is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
Received: from baptiste.telenet-ops.be (baptiste.telenet-ops.be. [2a02:1800:120:4::f00:13])
        by gmr-mx.google.com with ESMTPS id u10-20020a05651220ca00b004fbaaecae45si246631lfr.5.2023.07.28.02.19.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Jul 2023 02:19:50 -0700 (PDT)
Received-SPF: neutral (google.com: 2a02:1800:120:4::f00:13 is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) client-ip=2a02:1800:120:4::f00:13;
Received: from ramsan.of.borg ([IPv6:2a02:1810:ac12:ed40:12b0:7b7e:d1ff:7873])
	by baptiste.telenet-ops.be with bizsmtp
	id SZKn2A0040d1nm801ZKnTg; Fri, 28 Jul 2023 11:19:49 +0200
Received: from rox.of.borg ([192.168.97.57])
	by ramsan.of.borg with esmtp (Exim 4.95)
	(envelope-from <geert@linux-m68k.org>)
	id 1qPJdF-002ltR-W6;
	Fri, 28 Jul 2023 11:19:47 +0200
Received: from geert by rox.of.borg with local (Exim 4.95)
	(envelope-from <geert@linux-m68k.org>)
	id 1qPJdT-00AoEo-3k;
	Fri, 28 Jul 2023 11:19:47 +0200
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
Subject: [PATCH v2] Revert "fbcon: Use kzalloc() in fbcon_prepare_logo()"
Date: Fri, 28 Jul 2023 11:19:45 +0200
Message-Id: <bd8b71bb13af21cc48af40349db440f794336d3a.1690535849.git.geert+renesas@glider.be>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: geert+renesas@glider.be
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 2a02:1800:120:4::f00:13 is neither permitted nor denied by best
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

This commit is redundant, as the root cause that resulted in a false
positive was fixed by commit 27f644dc5a77f8d9 ("x86: kmsan: use C
versions of memset16/memset32/memset64").

Closes: https://lore.kernel.org/r/CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com/
Signed-off-by: Geert Uytterhoeven <geert+renesas@glider.be>
---
v2:
  - Update description, as requested by Handa-san.
---
 drivers/video/fbdev/core/fbcon.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/video/fbdev/core/fbcon.c b/drivers/video/fbdev/core/fbcon.c
index 62733f118833c6ca..f394c817bc074e0e 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bd8b71bb13af21cc48af40349db440f794336d3a.1690535849.git.geert%2Brenesas%40glider.be.
