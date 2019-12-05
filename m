Return-Path: <kasan-dev+bncBCTPB5GO2YNBBL6JUHXQKGQETMANDJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E144113978
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 03:00:16 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id u109sf513964uau.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 18:00:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575511215; cv=pass;
        d=google.com; s=arc-20160816;
        b=W175QZHC2k1w2OLLwPOdKf8kp2OIIxh3zkPjeWcA2A17qgFcxMTOVWkZaNasWd9o5d
         tRiRK+uVraHB2sH5/MIvzCz9O7FgwfzOSCkXZyIKEA4t4CDm6vZ1XuMfZAtPQOTeBzlc
         1mvvXMP67JQB+k0KuEsnnU4k4z5rZbzIs48OzpZtuIoG27Ppr+Nt/OvO/zZ0+z8BGI69
         gG5R/tqoC4Vkk51H2niUA7wHOzRxXJuLqB/9J4N0+BGnhAXVstIZ4yDsbs9AXxhXsmXN
         O03cmK3uez3/E9r9XzU8oPH6xBafbJ6vGbBxVwUeAIZYE4Ewf9ptN2xehWQho/0JYtm3
         x6jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:date
         :mime-version:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=hCTUlgGz1Xj69WpfeVr+Y7HRgcwpsFsfwCesCsBNUEA=;
        b=rL0ibFRnttrcNjo77dS+28ylcTLeI+Qv3uSaCkVQtjxodWqtWp9xKe9R7CKD3eOPvA
         ioj8GhYqnky8eK0yjdvBA805ldD7pB3pihwhXW1NIx1td31q2BCb1U416Mw53frGlhX0
         k5AI1PAldn6IecgTxNXhJKfaWlvRGKtCyOYhVdwHP2G+Yix2Db5DWSD64ntFiuLokM+f
         3yyCa/J1FvQVoI9sgV6NLZBMMVy0FuXYi+chGXMTYeNvlkZECaFeGpK3IiTLieLfvJfY
         xbNf1nPO/Ui6AxEpLAZMB6YK3VIQteYiF9pdtKmKdEOUznoa+ZAEFBlEkBIEwY4z86lE
         cmyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:mime-version:date:references
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCTUlgGz1Xj69WpfeVr+Y7HRgcwpsFsfwCesCsBNUEA=;
        b=XmHOXHs9mGtMvmbR8qdw2fX25hf1vpO1Riy/MS8x/3OjGo/WGytaDaQXnO+4ghQPsM
         LVTKAV3lmHLgUlzMNT3XnRB2va/bTI+96AfIgngF/LAeKOfxgfFS7zD5QdoDSh1nPvY7
         7mZOTsC8vxmAAOCCu+AKV0NMOT8wKul50dT0tftWn+cToPhXCHGlZftdY1CB8bLzTRl7
         UR9MGmEj1LpP1E1HgideH9ihuMDoqdCpCjTEbfdDwduWTeHOqBO7qnpz9uYo5TjqRV8U
         CE3GQ7FmOdqvTFzkX6OEiBr+iqs702b+VNv7idRsPI93q7JunuF0vwqjw3OY4gcjOdR6
         cT5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc
         :mime-version:date:references:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCTUlgGz1Xj69WpfeVr+Y7HRgcwpsFsfwCesCsBNUEA=;
        b=M5oTWcMgAFENEfVPBkvKkh/WZNja0bc/FaLb4DZGb4GYOaNfky9jYa8jL2rG5dKtKq
         8RqDxGebSQwCmcVeH1Z3Wznwm9sk7gNUXcK4uR4A7tN0Rz2GSpFBSZe/zc2/Tx9FSWTR
         IuL8dZ+WuaBzvrHNJc70z8B8wiVRvmvZU1OLYIBHrOQz9USqFZcLVSy0sEwbW7DO3fai
         oDEzhPmJO18isoSpZEtXo342yPMltSPvFC8nm9yKjIT9XwW3qxdolhk6P1rvFA29pM7r
         TzwjLfDUqpWYllqhD1DaTm/IA7GFKgUUWVlZbt/PN7VUpltvUuw/f5NWCmZVrsiPuhn5
         p0Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXQlqT8q0Is8OaiX1K9/85O3Vb3xlqltEhJsq8OttTImJaa/dBo
	qPXu4st7XW5VF6D0lUYZ6mM=
X-Google-Smtp-Source: APXvYqy8UXSWgtn2RkHZ/mxsB32JLtGT5C1Q3Yqcb1j7msdZJxchMUrXILnB1k1h3PUOLV1OhyS4Yw==
X-Received: by 2002:a05:6102:3034:: with SMTP id v20mr3750534vsa.28.1575511215435;
        Wed, 04 Dec 2019 18:00:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4e02:: with SMTP id g2ls111265uah.0.gmail; Wed, 04 Dec
 2019 18:00:14 -0800 (PST)
X-Received: by 2002:ab0:7559:: with SMTP id k25mr5173483uaq.41.1575511214806;
        Wed, 04 Dec 2019 18:00:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575511214; cv=none;
        d=google.com; s=arc-20160816;
        b=ehbxI4L/o7g0MMFLl0ceKvh+C8rm/fOzeT9HZ0MNKfySPE0iekdQ80KsCY4TkYZo2W
         8crTeHJrJpLnUXXVXH94qX0GUbg5T5bzuDWxnNhz8zrKWergwi75htQGhXj9UguXSxma
         TyPyTr3otdGq8M/mHXKDr2IhNYCILdTByYexuAZ29sAakf1eJT9euPDy8FjgLWpZ2SEf
         J/APwc3h0ic141Q33/WJbjumQNm+3+PTCxi7gVTm+zwN5BGHU0GFnYggpmcZzpVRqYss
         4yVCUMJFX9BT56r39kl2kn8C9XUJwvXLLE1sW6U9AMIS+0g8y7tAi4NxVBwDBpUmHvpl
         7V/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:date:mime-version
         :cc:to:from:subject:message-id;
        bh=Lb6CzwKABj1wc61zKNRHnm120DKXRjxT9mC9j51xRZk=;
        b=aEwG6kVCjKQR0AFxoDuiCjzmU9aCCZ8/AVCkCi5po4AUv9Kvz0S7lgSq3iHQ9eJAE8
         v1Hd/7QRsvrYFHuUZ6tLV+cjCVBg4MxrGNdYq4jmzw0xShVWC+GeESXVQ2P8G/vq15Ta
         ILRLdfMxVVOiNKu2gw2lWV0w6c+n6sfLXnht4w8h3M2Ht3vxk4kQBL/KwB7NSgUs3whF
         eL31eZEY7Kjj59Wd01zf9ZbAyDOwVCMC8Ym23jwW13iwjJx515cStbuUHm351VweD+MN
         yKfNhezfsMnnhg6lSydVC6thAs4hYaAr06kmZTEbm+Q8ICstz15vFKq0beiV2GOFahTY
         AxQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id h143si435050vkh.1.2019.12.04.18.00.14
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Dec 2019 18:00:14 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav301.sakura.ne.jp (fsav301.sakura.ne.jp [153.120.85.132])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id xB51xvft020982;
	Thu, 5 Dec 2019 10:59:57 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav301.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav301.sakura.ne.jp);
 Thu, 05 Dec 2019 10:59:57 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav301.sakura.ne.jp)
Received: from www262.sakura.ne.jp (localhost [127.0.0.1])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id xB51xvmN020973;
	Thu, 5 Dec 2019 10:59:57 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Received: (from i-love@localhost)
	by www262.sakura.ne.jp (8.15.2/8.15.2/Submit) id xB51xuco020972;
	Thu, 5 Dec 2019 10:59:56 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Message-Id: <201912050159.xB51xuco020972@www262.sakura.ne.jp>
X-Authentication-Warning: www262.sakura.ne.jp: i-love set sender to penguin-kernel@i-love.sakura.ne.jp using -f
Subject: Re: KASAN: slab-out-of-bounds Read in =?ISO-2022-JP?B?ZmJjb25fZ2V0X2Zv?=
 =?ISO-2022-JP?B?bnQ=?=
From: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
To: Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
        Daniel Vetter <daniel.vetter@ffwll.ch>,
        Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
        Sam Ravnborg <sam@ravnborg.org>, Grzegorz Halat <ghalat@redhat.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>,
        aryabinin@virtuozzo.com, daniel.thompson@linaro.org,
        dri-devel@lists.freedesktop.org, dvyukov@google.com, gleb@kernel.org,
        gwshan@linux.vnet.ibm.com, hpa@zytor.com, jmorris@namei.org,
        kasan-dev@googlegroups.com, kvm@vger.kernel.org,
        linux-fbdev@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-security-module@vger.kernel.org, mingo@redhat.com,
        mpe@ellerman.id.au, pbonzini@redhat.com, ruscur@russell.cc,
        serge@hallyn.com, stewart@linux.vnet.ibm.com,
        syzkaller-bugs@googlegroups.com, takedakn@nttdata.co.jp,
        tglx@linutronix.de, x86@kernel.org
MIME-Version: 1.0
Date: Thu, 05 Dec 2019 10:59:56 +0900
References: <0000000000002cfc3a0598d42b70@google.com> <0000000000003e640e0598e7abc3@google.com>
In-Reply-To: <0000000000003e640e0598e7abc3@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp
 designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

Hello.

syzbot is reporting that memory allocation size at fbcon_set_font() is too small
because font's height is rounded up from 10 to 16 after memory allocation.

----------
diff --git a/drivers/video/fbdev/core/fbcon.c b/drivers/video/fbdev/core/fbcon.c
index c9235a2f42f8..68fe66e435d3 100644
--- a/drivers/video/fbdev/core/fbcon.c
+++ b/drivers/video/fbdev/core/fbcon.c
@@ -2461,6 +2461,7 @@ static int fbcon_get_font(struct vc_data *vc, struct console_font *font)
 
 	if (font->width <= 8) {
 		j = vc->vc_font.height;
+		printk("ksize(fontdata)=%lu font->charcount=%d vc->vc_font.height=%d font->width=%u\n", ksize(fontdata), font->charcount, j, font->width);
 		for (i = 0; i < font->charcount; i++) {
 			memcpy(data, fontdata, j);
 			memset(data + j, 0, 32 - j);
@@ -2661,6 +2662,8 @@ static int fbcon_set_font(struct vc_data *vc, struct console_font *font,
 	size = h * pitch * charcount;
 
 	new_data = kmalloc(FONT_EXTRA_WORDS * sizeof(int) + size, GFP_USER);
+	if (new_data)
+		printk("ksize(new_data)=%lu h=%u pitch=%u charcount=%u font->width=%u\n", ksize(new_data), h, pitch, charcount, font->width);
 
 	if (!new_data)
 		return -ENOMEM;
----------

Normal usage:

[   27.305293] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.328527] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.362551] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.385084] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.387653] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.417562] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.437808] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.440738] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.461157] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.495346] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.607372] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.655674] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.675310] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8
[   27.702193] ksize(new_data)=8192 h=16 pitch=1 charcount=256 font->width=8

syzbot's testcase:

[  115.784893] ksize(new_data)=4096 h=10 pitch=1 charcount=256 font->width=8
[  115.790269] ksize(fontdata)=4096 font->charcount=256 vc->vc_font.height=16 font->width=8

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201912050159.xB51xuco020972%40www262.sakura.ne.jp.
