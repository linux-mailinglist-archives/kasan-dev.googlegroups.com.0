Return-Path: <kasan-dev+bncBCXLBLOA7IGBBHHNVDZAKGQER3HYOLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 90746160AF7
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2020 07:45:48 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id g26sf5812701wmk.6
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Feb 2020 22:45:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581921948; cv=pass;
        d=google.com; s=arc-20160816;
        b=L5/Y0zKJMT30U4/L38ZBoS00t1SPiIYiwHwk+d7r//KKe0Ag+M5CIYkdkUHIavW5uM
         91nxtKhnggRMXXmTq/surN0fjPH4pLEGMOgfG2x9tKPRvC+aoWArXoQ8tfkRWzUx+4hU
         BnemWsb3faIP23xNUQL4XSJiNggRZEEA3dc6sSQQyGsgCelorHzN5H2Py0gAI5gt1r9C
         actAXGIqyJa0+av0rzQe93r7dma9EkZ8xiQeiHaeWz3bvgeIOk+90qPGm8bYzvyW7qfl
         QUEWD1N5gsfqyXEHqpTvp1d3SIgDSJjzLOAQBpR6G44BUS54QrfzvdHOtZ1/O5AbneqE
         b3gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=qNnK97HyOU9Hwr6nPvtLBIk30cXsMudRhKvL3yD0AXk=;
        b=R+zKqEwph+FiM1WJRr/RbONEvkV7D/KPLTY5Egh57drSY2kKP4T53zo/cuB+ltO1CG
         8ttF0rqoFbEy+ddW/dVLoKgJDTl3Ct8Tx3CTEZG2wI/efyeHXZmNWgSThjxJ1TH39MxH
         KzwNLYMv3By6D5gqBeSFBJDRhTj/p+67F9VGe2Ob7BH34sU75ryTDZTgdR70kyOGqBVz
         q+Xwm4ioVRTNGY9Z1scKXP6EGkZoBX/gRQCsEUEQRpxB2oi/Xrw3u8a57DIHcGAbRlfJ
         augvSBYr8/TsGOOJV7nGg1ydL7iNPhqI/MQ3xHjW57uX4noQXo0DFQWLFPB2JXB5R2Ny
         m9fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Jkfz6bJu;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qNnK97HyOU9Hwr6nPvtLBIk30cXsMudRhKvL3yD0AXk=;
        b=m2xgubvyLQg5tYeuMxY8fg4CtC+VO/7++jEblYyppWKMja4eenbUJAm8XQofbAfn3W
         zEQcTaDwNyk1rnh6yACtsUfsMstPz98hUK/ouTFYL9/ZbXTo3PfS12KEJCNKpH29HrTw
         qFhrosxO6+32BktD9fcIT75zHKn7CddlnJyOnCOoWsukqfHC+B1mwcSnlqkz3wUV9Gnh
         3X1GRqRKoAIgI754Zau8pQiagMfnTymvEZJ5ZmK2/BRYPNDeDxk9JPEBfgC2lQQylKfs
         9gYyYXtqzNbxNBzCp6FnYjMM021r4S7R8V7GM2IwvG+JkVr10MD/qwarDLTuSO1f49tW
         2s7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qNnK97HyOU9Hwr6nPvtLBIk30cXsMudRhKvL3yD0AXk=;
        b=s9GIej1MazomDDXRicT1z5j3/1ICqXQm/liPpsRXIl8OK1gamsMkROvFXM49ANo1rt
         1gK5Xn9QyVmBWc2+QnWZzJ1qOgjT9V+TfC6PK5ApZ7idx7pL8/ygiiWwuYI2+i4txqPi
         ze0RLIPInSGOX5EjraYdmmu2X6b3SZrIWsYpRewBMoKk/1DjUUv2jjyk1MPgMy4zmPR4
         RjyP810AMuMY71i5PDJqx6em+7yqduvt8jvX3N+ZmBcjNM4suE7/Azd2RmKlbnzi0HHE
         1jeiTV3dWhYWiVd+RSX19rUFGTrnJohJ08xwxj1VNvz2xuB7jcV4XzPhftHO/R/kNW1W
         ORzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUiWXj+rhZpe/4ORLcv081ueD/Zyv9ESdfAB32/ozD7RIkye5J0
	ONk0CkY8KY9OFDROO5s/BTc=
X-Google-Smtp-Source: APXvYqxQXn1DjMPWyFUUGSul2Rb5EVEltFBexGs5ecMHj6DL0kbyroXIWLxf6CIkrbG7A4/E90AdWA==
X-Received: by 2002:a05:6000:1252:: with SMTP id j18mr21254961wrx.103.1581921948192;
        Sun, 16 Feb 2020 22:45:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82aa:: with SMTP id 39ls5034020wrc.3.gmail; Sun, 16 Feb
 2020 22:45:47 -0800 (PST)
X-Received: by 2002:adf:e382:: with SMTP id e2mr21096185wrm.128.1581921947693;
        Sun, 16 Feb 2020 22:45:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581921947; cv=none;
        d=google.com; s=arc-20160816;
        b=wkfJz8wPdXBbIMJkuE0/vv5bQuWUQE+ZvK9RQo8A3tFR70bj5JKuW8CA48/iq8M2yp
         9EGalbeOTW4nWpuYvKlQe0zs4Tih2VeHlWxrLVxL+ayC51Kr08CLYYGZ/VdZmzrpJaQ3
         9mzVEyg64/BsdHT1fuqk0nEoteG1TFZDx0urvN4d66aATcID+1SR4G3FpHN0QTRUH48o
         BDKxht58aILL0+YKQAEQlIFh6njO9MKIqGv2BCdAcTW3oV2ot+1HBA/WMDJyO3s0iZ63
         /w4lAAHfThC3VnFsKziZhTiZyVgpvTg82FkCOa/q0o1tnW7sPkXkQOR5nMEg4wLl2pAZ
         kQ5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=EaltpDTgnTrDBrsgY6UJWwdsZ8tEVbQgtxpz7LvsQrs=;
        b=QyPsClHsI9S79+k7loLt7Na9Krs60IXYIE3rT+PG5qBf6CHjcs3uflBKB3ryIuwmD5
         Azz77wr8sjm6RJUOzeA0Q1x4d43lUKeoDD8/+9iSGIoSjy2DLIgKv4UnerSSJUZvufdu
         lfLnfsjp7Zs8GcX9t7gmEjKk3gEnMOApIwOZ2JkX3Djj2E6GsXrk1LbixblJ5ZSLbZea
         31uEb5Bl6RF5Sn1NjgB+DEv0EV6nh9R097AxaY+2wtcAu7tfIYYyuLkKNC4I1NjgDEfG
         lwcJux731xkxKnekIXz/YFEISJD+Pqi/Q3j3F9q+XEokEArhChlL6voAtfV3GMwq9kZB
         BHVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Jkfz6bJu;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id i15si820425wro.2.2020.02.16.22.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 16 Feb 2020 22:45:47 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 48LZHp5ycKz9tyTQ;
	Mon, 17 Feb 2020 07:45:42 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 2CQ5mQXasQID; Mon, 17 Feb 2020 07:45:42 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 48LZHp4Ys7z9tyTL;
	Mon, 17 Feb 2020 07:45:42 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0942F8B79C;
	Mon, 17 Feb 2020 07:45:47 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id zPiOIOz8XNJK; Mon, 17 Feb 2020 07:45:46 +0100 (CET)
Received: from [172.25.230.102] (unknown [172.25.230.102])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D32F58B755;
	Mon, 17 Feb 2020 07:45:46 +0100 (CET)
Subject: Re: [PATCH v7 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Michael Neuling <mikey@neuling.org>, Daniel Axtens <dja@axtens.net>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20200213004752.11019-1-dja@axtens.net>
 <20200213004752.11019-5-dja@axtens.net>
 <66bd9d8eb682cda2d22bea0fd4035ea8e0a3c1fb.camel@neuling.org>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <a060e08e-c119-0d37-d220-409b3d7539d3@c-s.fr>
Date: Mon, 17 Feb 2020 07:45:46 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.5.0
MIME-Version: 1.0
In-Reply-To: <66bd9d8eb682cda2d22bea0fd4035ea8e0a3c1fb.camel@neuling.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=Jkfz6bJu;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 17/02/2020 =C3=A0 00:08, Michael Neuling a =C3=A9crit=C2=A0:
> Daniel.
>=20
> Can you start this commit message with a simple description of what you a=
re
> actually doing? This reads like you've been on a long journey to Mordor a=
nd
> back, which as a reader of this patch in the long distant future, I don't=
 care
> about. I just want to know what you're implementing.
>=20
> Also I'm struggling to review this as I don't know what software or hardw=
are
> mechanisms you are using to perform sanitisation.

KASAN is standard, it's simply using GCC ASAN in kernel mode, ie kernel=20
is built with -fsanitize=3Dkernel-address=20
(https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)

You have more details there:=20
https://www.kernel.org/doc/html/latest/dev-tools/kasan.html

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a060e08e-c119-0d37-d220-409b3d7539d3%40c-s.fr.
