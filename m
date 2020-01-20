Return-Path: <kasan-dev+bncBCVL5GMC3MJBBEMATDYQKGQEPT7W57I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x14f.google.com (mail-lf1-x14f.google.com [IPv6:2a00:1450:4864:20::14f])
	by mail.lfdr.de (Postfix) with ESMTPS id 883D2143232
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 20:31:29 +0100 (CET)
Received: by mail-lf1-x14f.google.com with SMTP id c15sf68172lfc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 11:31:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579548689; cv=pass;
        d=google.com; s=arc-20160816;
        b=u0i5FNgxFG5zk2peKMgnNCShiVuUGDOsIvFKyBNd+V4pdB/GlG2/bH5k7fETD1RmwY
         ZYn8qdooSZXLEYNriOHIKZb3rtZlWiWvUpwSjsfS5n7/65vvHo+xLyIFbupQUYdU9lbx
         5MP6kDu9exXengs+nsJXXTpuz1t9VqYenVNNedF4rgWVm2UP/0t2jHipItKITPZ6sB4t
         oZp6ED5r1EH0xDtSOJ7EEA4J1t3cvM9uDxjYtBxubgBpmz0ZeVk1bQMmP5X0x2A1dJLn
         vzLMhZRFDeJ1KWA/Z9CSWeqWvmn+7FNHKAI99U/mz/Yqg1+c6syc+VuoM6v1jw1PxGbH
         91qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=mXo0Mg6Q7ONaKtpDNkZuZuH/zgoyv5XyLhCwATD3dlg=;
        b=jerVblVBfoNmHsDYhspx5OvucnwXFXjvKidN0sJDtb78YLqc74op5sI+7Zjg31pURv
         f63A6iYX9PCzE39yAYFvMVmTLhlYE57hT+ATq9yQ2SEObn3LYLlcE9UE6syoW4FGPmNV
         fs58uW+OmLxbgcPw6PPMyPyff+noj0bxpwf+ok1wJem4e7+adCI2IZRtiyJ2vrPIAws4
         5QqeJWBFTbV9yA7yaTBIZydYSfLwwngTxW18lzX0WqZ9B85KqxOZ80uuApX+3vhbL3J5
         g0szq3y4OhRFJw5ni621BVHUTj/wbPB8LSEZCE8Qun7bytYnxfrms81c7LYlixUbbU/p
         mOtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=SrI6z+19;
       spf=pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::541 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mXo0Mg6Q7ONaKtpDNkZuZuH/zgoyv5XyLhCwATD3dlg=;
        b=FAwM30JR1J7Qxd65wjjPW1/dFg+DIlSbxYD9QKxF0pSpRjFuD/IwFic9EuaBomTLnc
         la1WTxI4cFOzf4OpQ3KCxsom/a0Cc2/ySNYCZUIE0KII1R9MasEa8ISY0eY4DJNltG9t
         cezXraiThIOnj4wCrqPGhExXbNWcG+m01yYdDwcgUREGLCHTtl3xPkzS2Ccomov4OXPN
         IgGzvm8tG8W12IjGlso41bZ9ZnAdpweCF1W2R9+bbaNm/3PXLO6BUUsSnCaCHjHAQjYo
         8FpYobTPT/Xovpl/gNdZ3L3ik7D4Euu1UV7XIs5I0MguN+49o4k2mWuU0xbAC6vZlakm
         ZvfQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mXo0Mg6Q7ONaKtpDNkZuZuH/zgoyv5XyLhCwATD3dlg=;
        b=VQOL9b/Xhdcp2RTq0p7gBqbhvKmCpljRBlOtQLi5erEIwIz2nKZm4qm0eHWfh1bRPo
         o7RUlnivFQmrMYsG+QgsvkIXkUWqpPv8NzsFWkqbsQQIR+gfeaYab74Fk9Fp8y7bRFwd
         wnWv5tCG4L9jYCEiM8eE3t05LueGJ47aQutNSp0vgRZpu3Pt/VuEnGlbRiD1mow+qoyK
         hPH8M6ktruismfCCxs472+WvL+vVwPZf82apG5pc5qhphU5B3AYwjLAQNFlUqvp+gOMB
         c+i2cFg4O4lTeCdJK0DECxXfuo4FcF8vXy90qBCaT2ToZIzs2PUj1/i3Mtfa5kh88jnP
         1sCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mXo0Mg6Q7ONaKtpDNkZuZuH/zgoyv5XyLhCwATD3dlg=;
        b=WFG7ogvA0Guwh9NA2PnPMiELF5HK75OKKI1fr4D1JMba60Nj5L/qWU6MMU6cHCrXpF
         c2cQylMuWTMdlAknP3xki8DN/1LSqbxfwHKFl5P9OorJ4mIfRh6GRW3zkWpA4PpW9hPC
         F/JcfcxKkxtLuamkg91GzgO2jpB3R4UlX1kQtz1Kia1Ekpqc5kquivb5OiPK79sAwJQ6
         7/BURRWqZn4PBxmKYqTxKMoHXgEb7tRSIMq9TdlYfdsxfa8PViBG6ylBREkA6uwrgW6V
         dHihWPje6RLxWqVRsTIXRobyaK8gN5CQtK2l2WfC8afmagbd0Xo0h31xqTzBy/WWviMM
         2r9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXiMd4qTkP6KbUzav90iQoG5+UqNVYEdRYarN0Smtyz6Q8Nalbb
	VTxLRH7Qxfv06cwMPrtjy9Q=
X-Google-Smtp-Source: APXvYqzCNBW+TxY8cgjkBaoo0+BJ0lOBqpUvw9jeLFzxz7IjagjqMBqzjYwD1gByM3R3q8R5hHiCMA==
X-Received: by 2002:ac2:5388:: with SMTP id g8mr461160lfh.43.1579548689127;
        Mon, 20 Jan 2020 11:31:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c74d:: with SMTP id x74ls3168442lff.12.gmail; Mon, 20
 Jan 2020 11:31:28 -0800 (PST)
X-Received: by 2002:a19:844:: with SMTP id 65mr497827lfi.20.1579548688401;
        Mon, 20 Jan 2020 11:31:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579548688; cv=none;
        d=google.com; s=arc-20160816;
        b=N0yl3o9pCBKtUVKBtPdd3Jsf3UoABwKZV7NzM0d0dXK0uqJ5yLhKzBj2frRO+0mlOd
         SkYx+ulsoy1HCQrH761dJlWIduW0KlP83YO/nivdrsrAVg9teXYxBqwXJKSUfbeZOTEm
         Lhquf0T5Pjx3zQHKITKf9j8aU1AzYdJ7cYfElEpkljc0wxhQzgeBk4wLrowk/UXLuAOX
         V8O/9K/TiEnABMpUg28+4MmueMgPaI5IRV6xOM37GyIjoJxKL5QK8rRn1BqH79QLV16e
         ucfnEtFbsBWNXtJ0zMXE4kkTOA7PYRzCxw4k9ZfPiW17YJLQelnLJ0ZvWFuecAww8ga/
         n6gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=z7I/Kq2V0EnXiuoACdRbnwoAql3KZ080nwyXVjlruyU=;
        b=q5Fq9bIViUdyfyzKnoeDUBpxDXgSEDQUsI8chmhYXiT84e8tI8SPk24uf2+8dDCHTs
         ND2Gr2wJD9snGxivCaP1i6YaCOQkHfiktWklK/Q+L+K7VjJSdMgS0ZTku7y9AulBRvhh
         ZYjvA39iQjD5EnwcexyAxzaYVe2pHJxOOVE38xivDz4o2JxNU8ocRVb4FvG6OkwAaDru
         HmA1LjVxsi2LieDaRCq9aeDbja9yYwRDlpxkf5iezcxg/D2H5NL7h8nuf29K3j4jRiZ9
         nTHwZLVcEcEOloaEvvPduM8wqbWfvbxaOFH3BuXCfnG6xmB1dkJsa3GahL2aOwMHx0b2
         YY+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=SrI6z+19;
       spf=pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::541 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x541.google.com (mail-ed1-x541.google.com. [2a00:1450:4864:20::541])
        by gmr-mx.google.com with ESMTPS id u5si1435285lfm.0.2020.01.20.11.31.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 11:31:28 -0800 (PST)
Received-SPF: pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::541 as permitted sender) client-ip=2a00:1450:4864:20::541;
Received: by mail-ed1-x541.google.com with SMTP id v28so548901edw.12
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 11:31:28 -0800 (PST)
X-Received: by 2002:a17:906:f241:: with SMTP id gy1mr926107ejb.345.1579548687843;
 Mon, 20 Jan 2020 11:31:27 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:a05:6402:22dc:0:0:0:0 with HTTP; Mon, 20 Jan 2020 11:31:27
 -0800 (PST)
Reply-To: mcclainejohn.13@gmail.com
From: "Prof, William Roberts" <eco.bank1204@gmail.com>
Date: Mon, 20 Jan 2020 20:31:27 +0100
Message-ID: <CAOE+jACYN-9AiP3uaE8Ut4Rjk53mzxareAyVj45HaD3RqW0fqg@mail.gmail.com>
Subject: Contact Diplomatic Agent, Mr. Mcclaine John to receive your ATM CARD
 valued the sum of $12.8Million United States Dollars
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eco.bank1204@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=SrI6z+19;       spf=pass
 (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::541
 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Attn: Dear Beneficiary,

I wish to inform you that the diplomatic agent conveying your ATM CARD
valued the sum of $12.8Million United States Dollars has misplaced
your address and he is currently stranded at (George Bush
International Airport) Houston Texas USA now
We required you to reconfirm the following information's below to him
so that he can deliver your Payment CARD to you today or tomorrow
morning as information provided with open communications via email and
telephone for security reasons.
HERE IS THE DETAILS  HE NEED FROM YOU URGENT
YOUR FULL NAME:========
ADDRESS:========
MOBILE NO:========
NAME OF YOUR NEAREST AIRPORT:========
A COPY OF YOUR IDENTIFICATION :========

Note; do contact the diplomatic agent immediately through the
information's listed below
Contact Person: Diplomatic Agent, Mr. Mcclaine John
EMAIL: mcclainejohn.13@gmail.com
Tel:(223) 777-7518

Contact the diplomatic agent immediately
because he is waiting to hear from you today with the needed information's.

NOTE: The Diplomatic agent does not know that the content of the
consignment box is $12.800,000,00 Million United States Dollars and on
no circumstances should you let him know the content. The consignment
was moved from here as family treasures, so never allow him to open
the box. Please I have paid delivery fees for you but the only money
you must send to Mcclaine John is your ATM CARD delivery fee $25.00
only. text Him as you contact Him Immediately

Thanks,
with Regards.
Prof, William Roberts
Director DHL COURIER SERVICES-Benin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOE%2BjACYN-9AiP3uaE8Ut4Rjk53mzxareAyVj45HaD3RqW0fqg%40mail.gmail.com.
