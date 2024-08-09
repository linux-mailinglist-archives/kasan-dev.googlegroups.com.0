Return-Path: <kasan-dev+bncBD47LZVWXQIBBYNW3C2QMGQEH3JDLUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D572294D165
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 15:36:34 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-7093d32519esf3330925a34.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 06:36:34 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723210593; x=1723815393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S7tmW9gMtJ1bYvX1wUcqZL9feAnweTI16I3UOGdS+SY=;
        b=NjKfzn23ydj2PVfpaaZZkU3wMpVXa0ttc8079Pmw9cE8Jrp1pwTwtFxXkw23pY4d5B
         rKYzUwgJUj21CrrX3UhqG8rBYF9O2WIpBLnXe4lZ/Vu+74EG3u+UHW20GQucmfX011nj
         2rXD7sxtP8L+UkJg4/Ro+vI5AsTzrxCMmmPybCYBMQlsLMysSjvqyV+ceIzGCeO6Kbe0
         KuDurKK2odu3P+Avr6AySh50hxEZkeFs63RlFpVgV/qL7+YCWP0BWzTlnY/YNMuHdT7L
         6vMEM6hkXzebD/mSGie+ps+vMLIhQryWXH3Uy/8ZxV9F4ZKlXTwBjIMTOACc808Eo0dZ
         Yuxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723210593; x=1723815393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S7tmW9gMtJ1bYvX1wUcqZL9feAnweTI16I3UOGdS+SY=;
        b=X1cnEtOLqA8a6cB1Hcedsc4xt6NYj81ZA/ZRy/zZil1eG4OMg3kyPfZM2tXYwbMh2m
         EKKhx7Zb3+wjBWEfMaZOXqP6LS42AwZbEqQw9smHdq01EO1gn1WXoJX3+1PXzYly9yOv
         qCfqXbnVl1ehXwza2iciOa5DDl0yUtP01uzAYUMiFv6JhZM4F8o4OHYS2kAIhInffpxv
         FCQdxTdIKa4rTAEaUQ1sa51MHm3dJhnu5Fir9+icdQYnsOdfw7ixl57DHoHviAwqW7e1
         LOyKtwfsesLG0QYrxo6WCyA4yop9GWpTMKXUvHr3BUhMCWhoW4Vz0O86lVkCBwEX1bqx
         ljBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723210593; x=1723815393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S7tmW9gMtJ1bYvX1wUcqZL9feAnweTI16I3UOGdS+SY=;
        b=J+/RVgh9jMC83QaJGGLUbbw9IvwzQiD/jFbRTbsZRzZv8TglfeIe8fKVjVQC1UHdLo
         ulMzlPrPnKuwZcpo5Pejmctty9H0fxxxEQXBjiYN7E+ATVEJun52MmTLZVUD6y6x8pZS
         FnobbK651MXGepe6M01ye6aE3tj4e+iGulHdNvoAKPsxhFQ4qwHlcrhuotZS+0DZ2jVM
         cI8XTvzPsWd1WonIrilUPdShd6qPeibVihSL3xNlfuNvx47NuKuA1rKTE61KwntL9hd5
         pB+/mywqabG7a2uxnoKT9iNgGCHPHlpWsyfeYyFx9hVj4KF/tjlfsH5+DVrIsJt7jOo0
         4Pqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCUqt4aEn+OLUVzW93yRoNBT02WxxYJCTfjQd3fadr1IO9moDWKuOYQr0i5Up2UQX+BCWlsU9HPD629XN556IPEJrErbp4hyug==
X-Gm-Message-State: AOJu0Yyy1P09ZcG3EcqFIyAf3Cch9Ni45X9gvvZw5dEH5c0BHHamBdDq
	buIdYDZKIFADevLVzQG1n5dv9Kkv7g9JGkTAHV/Q8EcT8vLAkZSj
X-Google-Smtp-Source: AGHT+IGeJ00lrGeKYp9K5mwUEN1lX0SSAra7ZsZCzXWCggQlTQt9w/LC8lzKeQ+wSypTVYxQnrcwTQ==
X-Received: by 2002:a05:6830:6018:b0:709:3d2f:7b48 with SMTP id 46e09a7af769-70b790f78c8mr2041171a34.24.1723210593430;
        Fri, 09 Aug 2024 06:36:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e9a9:0:b0:5c6:92d5:d6be with SMTP id 006d021491bc7-5d85129a327ls2135644eaf.1.-pod-prod-09-us;
 Fri, 09 Aug 2024 06:36:32 -0700 (PDT)
X-Received: by 2002:a4a:c191:0:b0:5c9:e1bb:4350 with SMTP id 006d021491bc7-5d86769279amr30935eaf.0.1723210592424;
        Fri, 09 Aug 2024 06:36:32 -0700 (PDT)
Date: Fri, 9 Aug 2024 06:36:31 -0700 (PDT)
From: Jeremy Shurtleff <jeremyshurtleff54@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <75a7e8f8-889b-4241-9c19-f13d00bb662an@googlegroups.com>
Subject: =?UTF-8?B?UmU6IE1pc29wcm9zdG9sINin2KzZh9in2LY=?=
 =?UTF-8?B?INin2YTYrdmF2YQg2YHZiiDYp9mE2KfYtNmH2LEg2KfZhNin2YjZhA==?=
 =?UTF-8?B?2Ykg2KjYp9mE2KfZhdin2LHYp9iqIC0gMDA5NzE1NQ==?=
 =?UTF-8?B?MzAzMTg0NiAtINiv2YjYp9ihINiz2KfZitiq2YjYqtmD?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_5432_1560393097.1723210591823"
X-Original-Sender: jeremyshurtleff54@gmail.com
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

------=_Part_5432_1560393097.1723210591823
Content-Type: multipart/alternative; 
	boundary="----=_Part_5433_1867119186.1723210591823"

------=_Part_5433_1867119186.1723210591823
Content-Type: text/plain; charset="UTF-8"

 wa.me/971553031846

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75a7e8f8-889b-4241-9c19-f13d00bb662an%40googlegroups.com.

------=_Part_5433_1867119186.1723210591823
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

=C2=A0wa.me/971553031846<br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/75a7e8f8-889b-4241-9c19-f13d00bb662an%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/75a7e8f8-889b-4241-9c19-f13d00bb662an%40googlegroups.com</a>.<b=
r />

------=_Part_5433_1867119186.1723210591823--

------=_Part_5432_1560393097.1723210591823--
