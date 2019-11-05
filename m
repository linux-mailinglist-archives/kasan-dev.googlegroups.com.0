Return-Path: <kasan-dev+bncBDS2JIVW7EORBI4AQ7XAKGQEPDMEK6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7FB6F051A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 19:32:05 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id a3sf13371485pls.10
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 10:32:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572978724; cv=pass;
        d=google.com; s=arc-20160816;
        b=C08F9Rt5PFAsadz70354Cx4GOdGfBWREcPV1/WP/m3U44q3xL2VATFcGlrNRXRuQwV
         gs87xccwL7p264GAHj4Uxu6K4Ew0u7SVRJaxQr/WxIk9WkHFY2yobRkqxaRD59/IRy8f
         kCapESHQkNDxV+yEiuLwYPodzmSj8bzjHT1nNa75NgWzscDg/9xM0M93ajCmGoC/l60+
         upCFwGPqxEd1G946wv3dvnnFDrSVqg+GwXq6xg4YvPuVBjnfGdX4LmW35w/tZ3uVyxQn
         CCqHXjfmUnP4QtxortLD9B4DWPeDDL3KiAwU7x6FAQw2yQEvSGn+pzM2uJc/7FbbzgWs
         2ScQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:ironport-sdr
         :ironport-sdr:sender:dkim-signature;
        bh=utwzft2HvudLUUM9YmhlBKCh7cADirM1ULZIofRSVQA=;
        b=NI4Iqv8pLrWPxxu/kT8LgTnM95LjCPKCA8dPzAHQMaK9MYOO/clkCowGUKl3Na9/Sf
         PlTkmkp5XlBcbV7sLBb84ZpLxNnV29s2C8TbkCd+X55nBmj85qMcHmUtGisYItxNVLx8
         dRtinUzXjPsoDwN8Wk/kWS8xHZphSeZJzkn6ibCqU0EZrYfzcOaPUv1sV4Pu3m3KB3ox
         vYtays9lz3R/P9wdTzyTKyNUV3vMmMC9Ti/diZ9B2TkjDY55SJYc3s3ega8unguWjqsl
         c6aLenIFYbGWhjo5fFI0wWwRpFUhLn7nXsc73Rj74Ij2+PoX2iPlAKfBVqsj7CG/lb4t
         /50w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of joseph_myers@mentor.com designates 68.232.129.153 as permitted sender) smtp.mailfrom=joseph_myers@mentor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:date:from:to:cc:subject
         :in-reply-to:message-id:references:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=utwzft2HvudLUUM9YmhlBKCh7cADirM1ULZIofRSVQA=;
        b=ZPRZCJNTzvSgE7pDqi/LsPDdzvn0Lob8bMUS5cVgNM5ESQyomGQDRBgyo1GEeI0iEz
         vV3iovaC68I3rwiWLgPepJdI9+JDF63ToLAqKOhgPM3Rh+AL2aI1xq1WiPaYFJ97ZeCn
         Wzg54fAeDCz8hiVp3lfizYgSGhqrfjuGEv2gs9KcDwsq/DYSzfik//SnZj0k175y0SNO
         5GzLrZN3i+NismnsGkedqsIGpfy7+/6sO/Fb8wBcxeqfyBHfpza+xnZubDeBCB20/mCn
         5oT2xlnPxF0SaSYM5jhYyemCeS/tZ7YDWrXgzyPrF55iSab8w8uGxzIPspVRKhHdFH4W
         4PtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:date:from:to:cc
         :subject:in-reply-to:message-id:references:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=utwzft2HvudLUUM9YmhlBKCh7cADirM1ULZIofRSVQA=;
        b=tZBAPN2l1GcEB3Dy+qLgPOUCXKzzaHOK9mDyRO2HyU3ZVOnUPo5+e7X0ZhybY0kaz6
         eb1SXXimMY55GQYqT0njd1pl69WZzcs51Fv+aNGQngUfi0x9wOni8ARFx4ZTM+WcATOM
         xwMk2MAHzd0+AKUUgE7Q9WpYIXyk8QbDOiQwfUu+5HJWFNFvFimrpy3dHGJ55hOO1CMu
         V5LcvJsrGzU0gilJXrd36TLVcw4aJlrXvQ9LN3Zy+UHrNpszWmKW9D3qTWyWLP3VtKof
         1It4Ot+NzHoT4DOK+n6izjOgRkmLNoc+d/S6D2DL/zuqUmE8FCgicuVFt2t3xP5bD6z0
         VNnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWX4WJxC5sAZvwybn/qeYoJnvRhMrTQPVMPCdut9eqwhlZWxDR4
	01pZk7h4ib/JHOJN2mmBdlU=
X-Google-Smtp-Source: APXvYqzyxaJMdrEHDEyMwnJrCZ3y+b8HrCU/VGrqjMj3BT5LlBtH22S6Xms0/5xxJgLadHthxfHO2g==
X-Received: by 2002:a63:fe47:: with SMTP id x7mr27908371pgj.112.1572978723856;
        Tue, 05 Nov 2019 10:32:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2ec5:: with SMTP id u188ls2235264pfu.0.gmail; Tue, 05
 Nov 2019 10:32:03 -0800 (PST)
X-Received: by 2002:a63:7448:: with SMTP id e8mr39202771pgn.268.1572978723372;
        Tue, 05 Nov 2019 10:32:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572978723; cv=none;
        d=google.com; s=arc-20160816;
        b=Wykd3Jd8HwMNC3ot2UmNmrSYjib8Vc2cZGJmi1RMMACQZII01b7VoGVbGm18KBqQ4v
         FUKYdDqQYG2838oUlUCPUJzAe2qvWdzp/HV2NvkxQMnK9PEn0Gj5ed7YoWsvOrY+pjKs
         jtGQu6FMW/wCcydjot2CzuFzB41l+850ptO1FXso81oglvSoxiYknQ+hZhRf3A8uoKfR
         cc7VSjmmX9uBfghIbjVrUuyV+1LC584GHgA2gmVwwKZ/jcNNlpDD9h+MADVCiMka5qxQ
         MKl04mwiX6NDbEyqikim81/85CfMWEW611FyiEWSLiiT99MRk+ELbupuoW/9ms9Q85Pt
         ZYrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:ironport-sdr:ironport-sdr;
        bh=QTRN3YamituaGivGZCAonI6uuStl/OBRNiMfLgd3zLM=;
        b=ls1GiNbSxjvKSCcY0U7fq+JmLuydSiEob13MYGaemk8rD+AoJZOendpVpxvz2cA9N2
         0OmGPg3CDuaFlRvg3wrgwKm9ViwhgfLzGne0f4N0G7/ce2YjZfcLqAeXngTOFC+BblG3
         /co20w/FdB4sOrm1Omd+IaR4g5Bj+l79h+8wVNAwW6S1ibBtAveZeKFgaH12m7T7W6nu
         Tk8nzVAk+F+LwXXP1+NIF6gXK+qFI+mGrODnwFj49JJuhRJt9o0lQbmgauONYVFc8eSy
         0F0DLU02dJAh1KDanE8sF/JkTiK3yvF0fISKmFNd108wJDTby5N+Vxq1dJUdQW7rVssD
         pY8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of joseph_myers@mentor.com designates 68.232.129.153 as permitted sender) smtp.mailfrom=joseph_myers@mentor.com
Received: from esa1.mentor.iphmx.com (esa1.mentor.iphmx.com. [68.232.129.153])
        by gmr-mx.google.com with ESMTPS id t17si1021265pgk.0.2019.11.05.10.32.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Nov 2019 10:32:03 -0800 (PST)
Received-SPF: pass (google.com: domain of joseph_myers@mentor.com designates 68.232.129.153 as permitted sender) client-ip=68.232.129.153;
IronPort-SDR: wEPhPh21iDPJCNosKZx8dR5+ii5SFz3wKmfX1nYY3AyJlSvOsnfl2Qu/Vg9T35VUxhQEVyEdNC
 Uz29OAi1F2/MWgWruaLWuw95iwBDROhguYKnmA9EO6GGyAOwVgIJtnwmU24VzAM97cZx7jEpLT
 LrnEeXOZoLjcuSSQGZyPBEjwCuCZVRQ/Y+0yusSi7j4jrx9/k8arINlLaRd0q/5OGzi5SnzZI3
 w/IWxaomKJEWSZTmwV3gV+maLi+xqPlRqcFvC+bAa6KT+mRu5JG8mShMdHkrz/OC0gO8z1diPe
 Rxo=
X-IronPort-AV: E=Sophos;i="5.68,271,1569312000"; 
   d="scan'208";a="44742523"
Received: from orw-gwy-02-in.mentorg.com ([192.94.38.167])
  by esa1.mentor.iphmx.com with ESMTP; 05 Nov 2019 10:32:01 -0800
IronPort-SDR: rQkuhp5YH/GoCIkQPE9m3wgYm52Njg0Avy/bc/BXqrtBn+aW0V//AE1Kp+S/v//qVfl/A1H/HS
 09i/8y3qU+XIUVo2pAXtVLPW/2i4m8SanJkhN0ZgAdjb/5xTGm0tzhHN/8l14dHrKkHkz/5b5l
 87gdV6nbKwUuiuT0Q0/MOwcq8I0z/jGmPuYMrs/qP0laCTWH7XduHro9GQwyhgnW0PshkyCduu
 F7BhEx5J9eaVreymXMp6wpvmXz2GuT2dXlK/Cnwc4Uy/BjqgTzhydBGyLKF5A/i6XBjq1/YZBD
 ZpE=
Date: Tue, 5 Nov 2019 18:31:54 +0000
From: Joseph Myers <joseph@codesourcery.com>
X-X-Sender: jsm28@digraph.polyomino.org.uk
To: Matthew Malcomson <Matthew.Malcomson@arm.com>
CC: "gcc-patches@gcc.gnu.org" <gcc-patches@gcc.gnu.org>, nd <nd@arm.com>,
	"kcc@google.com" <kcc@google.com>, "dvyukov@google.com" <dvyukov@google.com>,
	Martin Liska <mliska@suse.cz>, Richard Earnshaw <Richard.Earnshaw@arm.com>,
	Kyrylo Tkachov <Kyrylo.Tkachov@arm.com>, "dodji@redhat.com"
	<dodji@redhat.com>, "jakub@redhat.com" <jakub@redhat.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and argument
 parsing
In-Reply-To: <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
Message-ID: <alpine.DEB.2.21.1911051831190.22347@digraph.polyomino.org.uk>
References: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com> <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
User-Agent: Alpine 2.21 (DEB 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [137.202.0.90]
X-ClientProxiedBy: svr-ies-mbx-02.mgc.mentorg.com (139.181.222.2) To
 svr-ies-mbx-01.mgc.mentorg.com (139.181.222.1)
X-Original-Sender: joseph@codesourcery.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of joseph_myers@mentor.com designates 68.232.129.153 as
 permitted sender) smtp.mailfrom=joseph_myers@mentor.com
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

On Tue, 5 Nov 2019, Matthew Malcomson wrote:

> +DEFHOOK
> +(can_tag_addresses,
> + "True if backend architecture naturally supports ignoring the top byte of\
> + pointers.  This feature means that -fsanitize=hwaddress can work.",
> + bool, (), default_memtag_can_tag_addresses)

@option{-fsanitize=hwaddress} (and then regenerate tm.texi).

-- 
Joseph S. Myers
joseph@codesourcery.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.1911051831190.22347%40digraph.polyomino.org.uk.
