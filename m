Return-Path: <kasan-dev+bncBDIIND6JSUGRBIEM46LQMGQETVVYYKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B6081592859
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 06:05:53 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id p19-20020a05600c1d9300b003a5c3141365sf5605834wms.9
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 21:05:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660536353; cv=pass;
        d=google.com; s=arc-20160816;
        b=e5v7Lp+nAmdqL2N51nEgx+FUpagEzfRJfhx4lspbJk7k7C/9/2EBlf5pgdmMMxb6ky
         WXD5yeA6c1KwkOQUxCr5TQBVinLmI/T38yFMAQcaDYvECotnCBmjBBshxO6PYFSiDXR1
         8HWEUGHfg2miAW5/8UnEPgJkvB5iCP/rSNr9eouTVA2755f9+TBlYSPDozzrXCiOBXdL
         R82A+LKuZqGE4qKCSFAVK3WwD7bK0/ZnTuwTImU3AQjwRqEwX9/a9gUIWM8UmkiW8F0x
         JUYmZxVNPfmXt+Wbr5PvrqlBGaDLjcLRzyVn2kEFcNWHjdkiJfZ85XdxJn0RyMPd9rBD
         a6Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:user-agent:reply-to:to
         :from:date:mime-version:dkim-filter:dkim-filter:sender
         :dkim-signature;
        bh=AShOVzKTyaBgHQ9jYdxiVNbqUNRPQS5kwhug0XW0VmI=;
        b=BjrZ8iIgKZr1WN1mLzhjwqMjuDJffBuOSY9+SG5wAbYTE/sOiJSVrBW5un03QpUZx5
         r4MvFvtlSf9U0ktWXxgwhXXuKE0x+eiIsGb8bGIr5+kucwG8MttasBweKwTvGmu/nx71
         FdtS03SAUAwO8at0RAuhUE6TTCT9YxkvXrg5NyyXuagljUwyJrLsu8sX5Im1SrZ4/USP
         s5Xm8vWAEtohwMU3PPyLH1xXxFLjPTBT3EvwTtylZQcmaceaC9x9fQagyQP2CuUS8Eaa
         wv/vZH5X4Hawzs/dufLj2DD0UbEldYnQS684hab6OtNSiP1qEBJzJ/3gP7nb7d1b5NDO
         KoUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@uniecampus.it header.s=default header.b=YfxOmuj2;
       dkim=pass header.i=@uniecampus.it header.s=default header.b=PNX0OUPw;
       spf=pass (google.com: domain of lisa.rosso@uniecampus.it designates 89.96.212.244 as permitted sender) smtp.mailfrom=lisa.rosso@uniecampus.it
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:user-agent:reply-to:to:from:date
         :mime-version:dkim-filter:dkim-filter:sender:from:to:cc;
        bh=AShOVzKTyaBgHQ9jYdxiVNbqUNRPQS5kwhug0XW0VmI=;
        b=PIxk2cDZ4rOdhsCLXH0pspN5XXNffq649i1BrD7kxbX2uspd6suNhtaOeThpITkrBK
         J4vW8D7LuC54IbfmRdBYOcGXRmQiFe49K2EZ8wDbVD+YZ1x1KoMa9BsWy9tq3RSgyC5/
         rpA6yyVu3/dNUuG2xJM0jq4byVkjhxBWpNqFMWMMh2djKntBcYPGkngFr0KLGBppbmyT
         cTYcsdyGvTQHE9E5B/WKeRbQHPHZsN3NtjcwSdgOKdzWqg8rpHQxnzp5lfb+JdsYPr/+
         z6NCqtqXQc3oSZtWHvDTyLksDGcI9KAUnGoajpr0Plvy1aBLJCIH1nJp4WZLLLamKKsD
         Tygg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :user-agent:reply-to:to:from:date:mime-version:dkim-filter
         :dkim-filter:x-gm-message-state:sender:from:to:cc;
        bh=AShOVzKTyaBgHQ9jYdxiVNbqUNRPQS5kwhug0XW0VmI=;
        b=gFol6b71emjrMcObY6ZjzAvu32nA/rAGlybJt7kSHm6S1PWV6ZZJ0MVFZWqVx4+QiP
         86HvbPj1GrfiIkuNqo/o6LkoIhQDlrLI3ZRgOFQzz4o3OHhdPppOosAU5aCRC940myYC
         WLOCFXBFNlPqYYXDdiaEZmWMAMZX3JTo53zkbdC+/vUr7yZ+xMz5PMHDa8uzUG2XTjbb
         kB0sqh//eON+vONMY6IAl4MHNEv2FAXRi483rx2+OH7iVffYUhMrtINYQvvYw+tddIto
         tLh8+eMhq6KpY5DwCIT4zFsRLrdQowu16Zp4BMUobqb2dWA/ssZ0YIhcwodX98UNEE2w
         m68Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2WtCNPYW6n5JJYVCPJoyLlcne/YAsWGTh3mqtywnGEw5JESiEL
	xw/ydHY7cxtvtfdMpjOh/ZE=
X-Google-Smtp-Source: AA6agR5uRVfatIKtPbSqDrwP/p3wuuclLqidk6XlXe6FMinY8yKu4nypouLwUvK4zghEG0DvDiWz2w==
X-Received: by 2002:a05:600c:a4c:b0:39c:34d0:fd25 with SMTP id c12-20020a05600c0a4c00b0039c34d0fd25mr9274660wmq.172.1660536353188;
        Sun, 14 Aug 2022 21:05:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d236:0:b0:21e:e644:c8 with SMTP id k22-20020adfd236000000b0021ee64400c8ls13790413wrh.3.-pod-prod-gmail;
 Sun, 14 Aug 2022 21:05:52 -0700 (PDT)
X-Received: by 2002:adf:eb4c:0:b0:220:6aaf:ef5e with SMTP id u12-20020adfeb4c000000b002206aafef5emr7195556wrn.488.1660536352253;
        Sun, 14 Aug 2022 21:05:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660536352; cv=none;
        d=google.com; s=arc-20160816;
        b=qpX9oEJsbBuYZiwe/lQZtPiIccYxY7oi4oAvbwwrDXByQH0EfllMrBVQJpEs4958DC
         wGmzvtx6XUNOSUEGDbSdNhbq2WrMa6PZRF+DsY0tMCloEf36Mgdcp/l0udO+zM0yz4EU
         e8zrabY6i65TJko3zUpETubj/wdgWNdKIR7Kcbt0gZ7e6CMVMbFKUYQRO/Nu8iL7WVLN
         nIc61z7HOaZULNjENoCKVMEEp6bXh0JzhzPnFI0Vdx1ZnRN5oWNilHY/iwtkYD/2mXVH
         rQr5XqirkFYJkwsvVCOp/jlz3FWzf3kZEfY2T4zkTEXQ7kvPtpavlxQkzPnPxGDDAyu0
         UQCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:user-agent:reply-to:to:from:date:mime-version
         :dkim-signature:dkim-filter:dkim-signature:dkim-filter;
        bh=6/oBhBbjLvmy46cZYerjD9OOadBxjwqChe4P1hKkcXA=;
        b=W16cSkMYivIZj4d9XOLiz2WqEwmaP8HqZSTPnamojfL5yyx05QBtZz0+G6fV9E5YVQ
         0pWjwiYHBdYFUN132wYuwWCt3qVaVD85Pn4wNYuG9lCZMWkMVB/ONYa+o/IAehpxX/yj
         f04uIUEaWzA1JqFWWqUbkvoB+btGAusbph5ahy3pHmrePFCbMScHZDaNzPMXTIiBKbNP
         z68ZWnBrI3PYFisA2LmmCGGOLJAl/dgth5EqHgGxGmv5FqHMOLt5KQIh7nuW9Uu3hsOK
         8qVSPVHggZkIDu7wu8h9njr+312doZnvBRdJdzQNlOi9tL0DmxiCgpN6OTDtTuyZSsgC
         MZvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@uniecampus.it header.s=default header.b=YfxOmuj2;
       dkim=pass header.i=@uniecampus.it header.s=default header.b=PNX0OUPw;
       spf=pass (google.com: domain of lisa.rosso@uniecampus.it designates 89.96.212.244 as permitted sender) smtp.mailfrom=lisa.rosso@uniecampus.it
Received: from efesto.uniecampus.it (efesto.uniecampus.it. [89.96.212.244])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b003a49e4e7e14si992062wmq.0.2022.08.14.21.05.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Aug 2022 21:05:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of lisa.rosso@uniecampus.it designates 89.96.212.244 as permitted sender) client-ip=89.96.212.244;
Received: from localhost (unknown [127.0.0.1])
	by efesto.uniecampus.it (Postfix) with ESMTP id 8A00AC38C1;
	Mon, 15 Aug 2022 04:05:52 +0000 (UTC)
DKIM-Filter: OpenDKIM Filter v2.11.0 efesto.uniecampus.it 8A00AC38C1
X-Virus-Scanned: amavisd-new at uniecampus.it
Received: from efesto.uniecampus.it ([127.0.0.1])
	by localhost (efesto.uniecampus.it [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id NKVuJPA4X62y; Mon, 15 Aug 2022 06:05:51 +0200 (CEST)
Received: from mail.uniecampus.it (localhost [127.0.0.1])
	by efesto.uniecampus.it (Postfix) with ESMTPA id 6B978C38C0;
	Mon, 15 Aug 2022 06:05:51 +0200 (CEST)
DKIM-Filter: OpenDKIM Filter v2.11.0 efesto.uniecampus.it 6B978C38C0
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary="=_78925580f4b5330318924dbbefd91d35"
Date: Mon, 15 Aug 2022 05:05:51 +0100
From: Johnny ANGUS <lisa.rosso@uniecampus.it>
To: undisclosed-recipients:;
Reply-To: jonangus76@gmail.com
User-Agent: Roundcube Webmail/1.4.0
Message-ID: <f107f4d73fde07add8f8b97005e724d6@uniecampus.it>
X-Sender: lisa.rosso@uniecampus.it
X-Original-Sender: lisa.rosso@uniecampus.it
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@uniecampus.it header.s=default header.b=YfxOmuj2;       dkim=pass
 header.i=@uniecampus.it header.s=default header.b=PNX0OUPw;       spf=pass
 (google.com: domain of lisa.rosso@uniecampus.it designates 89.96.212.244 as
 permitted sender) smtp.mailfrom=lisa.rosso@uniecampus.it
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

--=_78925580f4b5330318924dbbefd91d35
Content-Type: text/plain; charset="UTF-8"; format=flowed

-- 
As you read this email, I hope you are doing well. My client is
interested in a ten-year joint venture in which you will serve as
investment manager and sole controller, and he will serve as a silent
investor/partner.

Respectfully,
Attorney Johnny Angus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f107f4d73fde07add8f8b97005e724d6%40uniecampus.it.

--=_78925580f4b5330318924dbbefd91d35
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="UTF-8"

<html><head><meta http-equiv=3D"Content-Type" content=3D"text/html; charset=
=3DUTF-8" /></head><body style=3D'font-size: 10pt; font-family: Verdana,Gen=
eva,sans-serif'>
<p><br /></p>
<div id=3D"signature">-- <br />
<div class=3D"pre" style=3D"margin: 0; padding: 0; font-family: monospace">=
As you read this email, I hope you are doing well. My client is interested =
in a ten-year joint venture in which you will serve as investment manager a=
nd sole controller, and he will serve as a silent investor/partner.<br /><b=
r />Respectfully,<br />Attorney Johnny Angus</div>
</div>
</body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/f107f4d73fde07add8f8b97005e724d6%40uniecampus.it?utm_m=
edium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-=
dev/f107f4d73fde07add8f8b97005e724d6%40uniecampus.it</a>.<br />

--=_78925580f4b5330318924dbbefd91d35--
