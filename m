Return-Path: <kasan-dev+bncBCT7LEN5Y4CRBB5OXHVQKGQEQN7FESQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id F2B8FA680D
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 14:05:27 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id n2sf2057913wru.9
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 05:05:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567512327; cv=pass;
        d=google.com; s=arc-20160816;
        b=f0ycnWndwMHyZCSXFW/0Vu/OyZn76na8ij85UtFPELipo7Y21zUWYKp5bfXzn0AHQO
         9KtaotSdzgdXcO5kCXTgqpXjGd6oGqCf8OD6mDdtm3AGAtoIdUzc7jajNd7pY39B7KG0
         MkHd0c81zzQFDspfzJGmL0kNdm4BnBJs01+b01OnjMYOGGOXKb6rsdl6E02H+huV8ur8
         zq7kBYSJJfoo2RErUzAJ8sUhhIwHV+Ni8XfQTnTlZEhhokUAyqaanRn7pW8QcEk0dYWA
         VUDyETvIStZvvQ8KX7PPwNYsspIrZHWJkAiRJGbgtUEbI9bYyYBCZhZ6l21QTqNwhs+B
         tzig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:mime-version:to:subject:from
         :message-id:sender:dkim-signature:dkim-signature;
        bh=Pya74QojMMRhSnqAzjLCM4r5WF+hcSzEokhiFkgp3Hc=;
        b=FSwAWFx2UJkOBOU2xXpRA/C1vG2k2vgcHsTfqXeTxzkUwuh729s925EQzii2n5eLwT
         fkjSlHGUrtNLHkxdRyeAIHK4zWSBz7ffZ7KZusVouuvpopPAoXg/9+N7ZlWM5F/PyvZ8
         xvnYd3W33gVn+XV81LhNeQk6Nm+Cy6MkCbDGGfNPbfBfntnMFf3mOJchT1O91Ixc/5Y3
         z5er+xnybcrEMmADQv9sPthVbdHBPEDswtOK34zTwZ+nqIcyMONEvIve5wqxwfxhHE+h
         FUsedlhjF2z5gRD+q/uiBsFuqJSUcClAcerSey/QrH1G+HaPJ+GRZrYcK+49yyR97ang
         2Urg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EbCG2qZQ;
       spf=pass (google.com: domain of beautiful.lady1441@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=beautiful.lady1441@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:from:subject:to:mime-version:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pya74QojMMRhSnqAzjLCM4r5WF+hcSzEokhiFkgp3Hc=;
        b=sX13dlPYCEm6INq2D0g+nf4rWfJ7ibGFhEVRU7CM2An4vR8KN8T/CGQmIPKjp4cgow
         2E6rmJQjYF0FBlNcQuGDvVp+7DatWvt7sJGPr47no3bwiv2SII9h6hQZIbXqJVCEdaWG
         SHYS+B+kzVmHNcwMUodddnOGdZPGV3/Ff6BfU68x/z/4eIUAQCA/v/mAT4ZvyioypToW
         4eZpT5+QmUwgNjKkD/a7AgsJfmODFNSUr70BnQqOzQ6uKLbTe0lTXIXbCT80yONRgaA4
         8DAA/8YwamZ61xsNVCvU4vxSsYETdc/JLWzw+IPZ5Fy+JxTDD1fGB/jijvdxe4F7MnjD
         0cMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=message-id:from:subject:to:mime-version:date:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pya74QojMMRhSnqAzjLCM4r5WF+hcSzEokhiFkgp3Hc=;
        b=AQ1BfTBuDxRInf/cHr+IAkZbnvM8x5L3awqat8Qrl7rCsRI/gNUN3BstruUJOo2eKa
         Ai7OsfCLqmCvdt8n2ZohKyEiKmiYDl3vA2F1JJoWmRye7Rv+7Z7WWCDY2VKq6fmOwVkm
         glrlMXA3SaEODx8qRjijWdbCfChZoD5jt7lbOrR8IxSjsWCS5Dsi76OT8HoTe9A/++bY
         eV35tW+ZLTcu9W5tNa/whmjY2VRHExwvGh1Ve6MYI56z323w/ikuv5RBXokBXXGOIC5y
         gceETyf7HCMYEQmBWchANxRd7OA8yA+t6POqWYJMG3E9eYAlMKO1IoRcSx7S4Ve0/wR4
         fyKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:from:subject:to:mime-version
         :date:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Pya74QojMMRhSnqAzjLCM4r5WF+hcSzEokhiFkgp3Hc=;
        b=KcEzXIX1TLNuVuJE2tEuIoNiZKYiPod7mZWahTJJm9WoNcmlM4Ry0f0gETq1veKT3b
         33Q2eBiYPSNNxzn5MEuUdma0ifo6Eb1YT5dbwQ1tRqM5cRmECA8HBckLMG5B6mDv6t5a
         0TC1SrZ0KzmUil6iiuoHOc8AtqML2aduKL7PYL3o1qXKuYzQsYruMGAU0nS0Ukar2H5h
         MCPRC4/1BumVtYPknA2b3SmY/2wEK9Xf2K5jsigMUQ7gkoEeF9c+j9NzgyUEoy+EgMbe
         a+9Y2bwxhj9dFNJfo/lKNP2ucFJsMF8w20+nnADMiuWzvlGtQR+sWJvw7xWRtZd9na61
         8+7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUCUZEl76AV/csyt7bDlwyad/CzvcyPRkYkHOLQOUqJoKoY1zdb
	w06yg00cXB/LpP+DtgDbRbk=
X-Google-Smtp-Source: APXvYqygt/7RmGg1e+aoecUFK4/qjh746SFrLloTGgOg+PYxfTclSj7QdM1zeugn+1RVCjc1GXSypw==
X-Received: by 2002:a5d:4382:: with SMTP id i2mr26901745wrq.297.1567512327675;
        Tue, 03 Sep 2019 05:05:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6c06:: with SMTP id h6ls5503367wmc.3.gmail; Tue, 03 Sep
 2019 05:05:27 -0700 (PDT)
X-Received: by 2002:a1c:6782:: with SMTP id b124mr44542064wmc.143.1567512326991;
        Tue, 03 Sep 2019 05:05:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567512326; cv=none;
        d=google.com; s=arc-20160816;
        b=Yq8BT4ORzqaouS1+h3TVtldZFzSLTjL6DS5fbpZwyHudakyIbsyRuBVH3l3dPwgM6e
         3unJ2fWxKQFW5o+tXa1r75YTq30c64mqILZSh1ke3IutxQ52YW1FXUfTVdwb76Ny7Pz4
         2hqENldq3E0cfn2J4ZeC0kpEa6OUozmrevSBA+SVm/PW7MTTKVpl8V2LvWVBmQp62E7N
         Eqa3yrCyn6wvesH13qISu//3fuOXq+sQp1JnHxSteGkdtBHCVvIfrJ0GI/DfPMj2ljqW
         rZzDnDIAjSKNqdLleU8zs7/vle/qu6J8HJ2g1TJd1jeOjh3eUXWyhienZFrCxmA5MBbp
         SV2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:mime-version:to:subject:from:message-id:dkim-signature;
        bh=IrbAji6NBnNtIvUv3wX+Po/IH0cI2uChMFWzBPrAJfs=;
        b=Jblerka5hcULTYyStfRpvTPtkVg//2RFCsyIyNezoj+TgfttQjGKOmt3FIuJd7icN3
         JM7XjLnbKx0b5q4yEMWojCgHcwk0ZF6Qb9gYMPnQpUIcmEy8FkgcvYeiS37GVZyqX/Sc
         z1pfLDq9HDWdNufOBTg2Pin2mykPCjBeRU/bGj0sFSMtiZ2FJM0egRNqo5NtKtlMi7fc
         6t+4A6XiAXR9kY+jyfbC7xS3UTxl8/PneJsl0QJVjJ+25z4nltintZJhgEvQh01MWCnw
         JHiDFv4YOUwz7krMaEe+Edh/S5JseB+/MAeBjSxyRYUIy5ZfTX9g/Uy9+jKxui9h22g9
         E37Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EbCG2qZQ;
       spf=pass (google.com: domain of beautiful.lady1441@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=beautiful.lady1441@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id k13si1103396wrv.0.2019.09.03.05.05.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 05:05:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of beautiful.lady1441@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id j16so17193437wrr.8
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 05:05:26 -0700 (PDT)
X-Received: by 2002:adf:e790:: with SMTP id n16mr33807665wrm.120.1567512326469;
        Tue, 03 Sep 2019 05:05:26 -0700 (PDT)
Received: from 41-218-255-237-adsl-dyn.4u.com.gh ([41.218.217.167])
        by smtp.gmail.com with ESMTPSA id f15sm11431277wml.8.2019.09.03.05.05.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Tue, 03 Sep 2019 05:05:25 -0700 (PDT)
Message-ID: <5d6e5705.1c69fb81.7ef49.19ed@mx.google.com>
From: Bill Maclean <beautiful.lady1441@gmail.com>
Subject: Urgent Inquiry
To: "kasan-dev" <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="ySK99Ur5MUug1shX=_wVUweN4rkmVXZuE2"
MIME-Version: 1.0
Date: Tue, 3 Sep 2019 20:05:26 +0800
X-Antivirus: AVG (VPS 190902-8, 09/03/2019), Outbound message
X-Antivirus-Status: Clean
X-Original-Sender: beautiful.lady1441@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=EbCG2qZQ;       spf=pass
 (google.com: domain of beautiful.lady1441@gmail.com designates
 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=beautiful.lady1441@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

This is a multi-part message in MIME format

--ySK99Ur5MUug1shX=_wVUweN4rkmVXZuE2
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hello
Hope you get my inquiry, I want to know whether you sell (Slab Buggy)... Email me the available sizes/models you have, or a link to look through. Also want to know the types of payment you accept.Hope to hear back from you soon.

Best Regards,
Bill Maclean



---
This email has been checked for viruses by AVG.
https://www.avg.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5d6e5705.1c69fb81.7ef49.19ed%40mx.google.com.

--ySK99Ur5MUug1shX=_wVUweN4rkmVXZuE2
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Content-Disposition: inline

<html><head></head><body>Hello<br>
Hope you get my inquiry, I want to know whether you sell (Slab Buggy)... Em=
ail me the available sizes/models you have, or a link to=20
look through. Also want to know the types of payment you accept.Hope to=20
hear back from you soon.<br>
<br>
Best Regards,<br>
Bill Maclean<div id=3D"DAB4FAD8-2DD7-40BB-A1B8-4E2AA1F9FDF2"><br />
<table style=3D"border-top: 1px solid #D3D4DE;">
	<tr>
        <td style=3D"width: 55px; padding-top: 13px;"><a href=3D"http://www=
.avg.com/email-signature?utm_medium=3Demail&utm_source=3Dlink&utm_campaign=
=3Dsig-email&utm_content=3Demailclient" target=3D"_blank"><img src=3D"https=
://ipmcdn.avast.com/images/icons/icon-envelope-tick-green-avg-v1.png" alt=
=3D""  width=3D"46" height=3D"29" style=3D"width: 46px; height: 29px;" /></=
a></td>
		<td style=3D"width: 470px; padding-top: 12px; color: #41424e; font-size: =
13px; font-family: Arial, Helvetica, sans-serif; line-height: 18px;">Virus-=
free. <a href=3D"http://www.avg.com/email-signature?utm_medium=3Demail&utm_=
source=3Dlink&utm_campaign=3Dsig-email&utm_content=3Demailclient" target=3D=
"_blank" style=3D"color: #4453ea;">www.avg.com</a>
		</td>
	</tr>
</table><a href=3D"#DAB4FAD8-2DD7-40BB-A1B8-4E2AA1F9FDF2" width=3D"1" heigh=
t=3D"1"> </a></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/5d6e5705.1c69fb81.7ef49.19ed%40mx.google.com?utm_mediu=
m=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/=
5d6e5705.1c69fb81.7ef49.19ed%40mx.google.com</a>.<br />

--ySK99Ur5MUug1shX=_wVUweN4rkmVXZuE2--

