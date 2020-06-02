Return-Path: <kasan-dev+bncBDM3P4G7YIARBMN23L3AKGQELNBCQ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F1B91EC200
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:40:50 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id x186sf8540339pgb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:40:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591123249; cv=pass;
        d=google.com; s=arc-20160816;
        b=M985R/Lkq5RGBMzqHb94Swivv0mOKMRTlLxmuqzenC4JsEoySuYgMqqNjxcEorW5kc
         oQUXPmYlE1keHjXP4wRr1ztVDsYfv6+Og82brgNwO56d2JaSwMpVbRRsl1/s77vGfnqH
         Cj1pwq5rCbjGihdPgRdUTNJVTr54KvYQwulTf1q7ndnS4mAj6rqsAiglM98bdfo0M2E2
         T9RtSrAa5lvMPWXLsFCgtEBOr8JCa870z16NIJIooiw2wCujld1w/htJf7fkOlu/6Hw3
         Xk3H40y0VZ3ObWJNLO3aEr+lqFZfGbI1N16ej24wAvdcFJXZvdvoKWJ9hZkQ0wl+BrFk
         YLuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:subject:to:from:sender
         :dkim-signature:dkim-signature;
        bh=TPCqHhdSsXjN4ON4DXmnnoczHWWclLY56wi5jeECoHM=;
        b=ixAe+HwZGYwxmR1WBKkiOr+chpi9pl0nZB2DDkTHcSOWucEKB3K+6ceKlz9PWR0fSs
         Hb3C9KjL63g44AcA9+soNTbfGqc51/zhRoFHugFAwN+lbGjv9U7s50ydHyYDCTIbdxz4
         bZ2JWcHvZenXctJfEYJt7ZTi0F5asnlk1M8d7epNcFQIgE1o2oChvld18mZiBokk/GtM
         amSl5UlaYBYQI+SMAuV28vj188cB6m09JSil1foGMnDAWLzzu/qQP1BkO/UMafRXWbfh
         cOh25E8jpgvXxcKb6pw7Sa5//C4tecnKG3c6gvQiyq34yqF8ZeuJHFSfDKo/ItfKLpp2
         lD6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nrzHBq67;
       spf=pass (google.com: domain of samclaughlin2323@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:thread-index:date:message-id:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TPCqHhdSsXjN4ON4DXmnnoczHWWclLY56wi5jeECoHM=;
        b=Nv0G0u9hGZ8pdXhglue+kUC8jMROApejeEaBVxgIBAWiC/c7JW4qmPa/c7ANdz1UTE
         wAVwIh9vYL68ocZwE3Tv4qKvVRbm2zec7q/pH4y5l4zPjqKFNPFtdJQYNMSR1trhtlaf
         ae2Gf6v+FUX4p2Ul6UZfbsthr4cObR+uuOMJ6cv9FnxWZUIbDwXn+oBggJFiiREBtZlu
         30vsnaGRutg8eSNLG4Omn3aC/WoBYzUNcFF0GT0fqOPjfXESfZaA6Nzq4R/xqWPqwoCO
         MXf/xrGIKUH1XLajy/FbciUnOTxGvT5s50kNd4SFA64/1LSjRA8GbEzGICprmiZ+DqsD
         Jktw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:subject:thread-index:date:message-id:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TPCqHhdSsXjN4ON4DXmnnoczHWWclLY56wi5jeECoHM=;
        b=ssGI0Jrpur+vTfsvQiQgHNYKl7a+NMv86rJ/MLMB9KJcH+p6uUA7/rYjDEU61p9mvK
         On03OB/ulq/wYGujml1aqOcXlk10Lvrb1BGhk6rN9XcZ44qTlakPUHwp2LjQqoegHXEK
         KxIc9/ZHcN5XB3+pmUpJaIDf6zpnvC2NniDpYREcFqXyhP0UWK7BBQDS5EA2XMkIiKSb
         OlO+NdaJVNpwb8E9QAYPkYYx0l4VmHp91uMR4b/0TMGH9HzkumLKr017sLgdBR3JKBdM
         orqhjZ6ffkrhtSyKkYz63PLlaD72GSV8Ui+wZxXKfqW/zVziaHaQjlErytvZaesa51h0
         3o8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:thread-index:date
         :message-id:accept-language:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TPCqHhdSsXjN4ON4DXmnnoczHWWclLY56wi5jeECoHM=;
        b=CRSuiNqPdwr2Pc3REyyfF5vrBySn9v9XBeMIJNIUEf0CCE9PY5DZ4fiP+Cfu0XFVcG
         fE/wzPgUoVV+PXsngRsTCRciIWMxzaQ1VcRfZspolzJSMEm0dAZPQary5MKOYnTVBjRQ
         crMxon+d0CWETakqKkGiZdAblmkS0UDItfOoZALbmguenEN/l6n3OUkc/16N8Dc5W7T3
         FdB79peDvFGzhR1qSOw2m7+CJuVGggTrbAVJS2lua0lagbPYfJWHg7hgN7cJ6Cc15lHT
         /MS6CYYrDonfs/tz78EZ5LV97oDpio0gYuvnqzCHJQQFmw3JVlmta3ClOjKxUl2IDeQ5
         KzXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311gA8qkS/pHuJ40D48egx+fmvHDNzcr0ausmpdbaTzEEObxLKK
	vB5mdhvN+mqeQsyXDZaOOho=
X-Google-Smtp-Source: ABdhPJx+nGiRLhnJL8Cz5AIol0Yzp8xHpkvBAFJlr78RzJ9AdjlL8ypOXepRULVBr3V9WTsiqlU7xQ==
X-Received: by 2002:a65:46cb:: with SMTP id n11mr26072750pgr.37.1591123249165;
        Tue, 02 Jun 2020 11:40:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:521f:: with SMTP id g31ls5448093pgb.2.gmail; Tue, 02 Jun
 2020 11:40:48 -0700 (PDT)
X-Received: by 2002:a63:8f46:: with SMTP id r6mr26111806pgn.257.1591123248554;
        Tue, 02 Jun 2020 11:40:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591123248; cv=none;
        d=google.com; s=arc-20160816;
        b=Vzb4Rcho7jp7Jj4Mt7bUYuTxXmZj7wpHev78atQx+2nNa4HSzwySr4q5boQFRiiGYL
         SA2dca55dFT5n7d8ZrhBi7rcy7rOz/tSilyjKWE8gv2AhLlws05pQ7kcFgszTre6w0JN
         YNBhVkgwEE6WYLvkWoswrzQIAuTbsfppzmryQ+7OmxTN7OodqRoAxpGb11+GrE9KVTfV
         2zgTP4X7GiM9hYebeKh8Fbx1Jt4kojWLEBFZKYkc7TCDggnvOF3wEIcY+br+DGSkB2si
         5NvL/4zi3HyPB9ob4HPdhQKTyIIV5dNaLdCxtvTksqYXoGplX+PpL/rSsr/p9QWMwb64
         LA1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:message-id:date
         :thread-index:subject:to:from:dkim-signature;
        bh=/prxae0v4bUg1PclLhVHStiyYXhiBYFQS/9sT6iOFMo=;
        b=wu1duBDB8OBTOMMIIf+1xqPUKq9F7TeZ9D9amrnJ/5Z3YkM7BsvSoKFBY0DoGp7AaX
         Tl2tng0I5G/hS54Dhl4vp33n1Pc7zqxY80btqqagCBlN1G8abqPc8wyGA1/kOiSHtnzT
         LMfanWznD2N7/tIh9GZdKUmzOEEfdUdSJOWzIwMG/dsRmDIVOpI7t7pkNmmYfqrdu2+5
         HDfHBfXnoJSXMLpLB/DcsM9uV0NIn5qWAG3LolCZ4fO/eh7AibbuxgH0D5gHA9S+KNwt
         SoweXfoTHD68JXEpFmeC++iJbXoo6aza1pDdYgOAdJ0VQ2JEoi73Ow5fv7btSXU8Jdg2
         KJHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nrzHBq67;
       spf=pass (google.com: domain of samclaughlin2323@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id m204si143922pfd.1.2020.06.02.11.40.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:40:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of samclaughlin2323@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id d6so1947505pjs.3
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:40:48 -0700 (PDT)
X-Received: by 2002:a17:902:b40e:: with SMTP id x14mr16235425plr.285.1591123247686;
        Tue, 02 Jun 2020 11:40:47 -0700 (PDT)
Received: from BY5PR22MB1889.namprd22.prod.outlook.com ([2603:1036:307:40a7::5])
        by smtp.gmail.com with ESMTPSA id 15sm2991157pfw.189.2020.06.02.11.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:40:47 -0700 (PDT)
From: Santiagoht Mclaughlin <samclaughlin2323@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Subject: 
Thread-Index: ATA1NEQxEHhTsl7GSPwZHkJEzFCXuQ==
X-MS-Exchange-MessageSentRepresentingType: 1
Date: Tue, 2 Jun 2020 18:40:44 +0000
Message-ID: <BY5PR22MB188975ED7BAD4E488AF6859BF18B0@BY5PR22MB1889.namprd22.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-Exchange-Organization-SCL: -1
X-MS-TNEF-Correlator: 
X-MS-Exchange-Organization-RecordReviewCfmType: 0
Content-Type: multipart/alternative;
	boundary="_000_BY5PR22MB188975ED7BAD4E488AF6859BF18B0BY5PR22MB1889namp_"
MIME-Version: 1.0
X-Original-Sender: samclaughlin2323@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nrzHBq67;       spf=pass
 (google.com: domain of samclaughlin2323@gmail.com designates
 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
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

--_000_BY5PR22MB188975ED7BAD4E488AF6859BF18B0BY5PR22MB1889namp_
Content-Type: text/plain; charset="UTF-8"


hnjgfjhngfmh gm hgkfl'hugkf
lhgf,mnh,gfmnh,fgmnh fm h nfmh gkhoiguhgfm hgf h gfmhgfnh gf hgfklkhl'fkh;
f
hgfm hgf hgfmnh/gfkhl
gf


Sent from Outlook Mobile<https://aka.ms/blhgte>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/BY5PR22MB188975ED7BAD4E488AF6859BF18B0%40BY5PR22MB1889.namprd22.prod.outlook.com.

--_000_BY5PR22MB188975ED7BAD4E488AF6859BF18B0BY5PR22MB1889namp_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dus-ascii"=
>
</head>
<body>
<div style=3D"color: rgb(33, 33, 33); background-color: rgb(255, 255, 255);=
"><br>
</div>
<div id=3D"ms-outlook-mobile-signature" dir=3D"auto" style=3D"text-align: l=
eft;">
<div dir=3D"auto" style=3D"text-align: left;">hnjgfjhngfmh gm hgkfl'hugkf</=
div>
<div dir=3D"auto" style=3D"text-align: left;">lhgf,mnh,gfmnh,fgmnh fm h nfm=
h gkhoiguhgfm hgf h gfmhgfnh gf hgfklkhl'fkh;</div>
<div dir=3D"auto" style=3D"text-align: left;">f</div>
<div dir=3D"auto" style=3D"text-align: left;">hgfm hgf hgfmnh/gfkhl</div>
<div dir=3D"auto" style=3D"text-align: left;">gf</div>
<div dir=3D"auto" style=3D"text-align: left;"><br>
</div>
<div dir=3D"auto" style=3D"text-align: left;"><br>
</div>
Sent from <a href=3D"https://aka.ms/blhgte">Outlook Mobile</a></div>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/BY5PR22MB188975ED7BAD4E488AF6859BF18B0%40BY5PR22MB1889=
.namprd22.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/BY5PR22MB188975ED7BAD4E488AF6859BF18B0%=
40BY5PR22MB1889.namprd22.prod.outlook.com</a>.<br />

--_000_BY5PR22MB188975ED7BAD4E488AF6859BF18B0BY5PR22MB1889namp_--
