Return-Path: <kasan-dev+bncBCXLBLOA7IGBBKO4X3XQKGQEM72LEAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 10611118B38
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 15:39:38 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id b131sf1069679wmd.9
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 06:39:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575988777; cv=pass;
        d=google.com; s=arc-20160816;
        b=PROvoHKU0ekGPP70jwKsmpikKoTQvXgcm/+w1HNWs2vqB98CQnxHQTv3X/I2XbPnd7
         yW19ZvINH0uRDCnyqoeN+0v4T2kU8N8UqQm2mvdh4aA0Nkp4sZzQOJfiOWCnrcCFRJO7
         ehJ5px2eBQpq0M4aO5Mjrs2E6jYQM9obEzF3z985B2h3aMiGL8sYL1hNeF+378hQPO8q
         /9TmeKGUsJDURS6PXZ5paEBYf4DCh+nHK/ctXHA6rg7ij0SXxJO9b7ABUorsS3a9BUkW
         aC7E+rzlLepcMm30Y++tEAoC6umsy9PLhdk/uDrBqnYy/TWJlL5GEdAGYtvDuaqgPjW9
         sE7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=XviR8X6BWscvCw9S/VSnsXo1kyFt/Ons9DuG0IgW66w=;
        b=SfFwaTv3iZ0tS4NMq4NyJ1OQRz/fmjlisL/Rsk4A1VclxK1FQPXHOGF94DrxhYQpCA
         6VzyeH1YzD5xCWAz5XRfos9iOwICCKsNm5jY2dvPPStgwnBJv8/m+GC7dK9w+xV8v015
         fP2JgGCORy952hCDHtC+DxoD3k9inhCWHb4RNBmmgTv9WJZaeDuWx1BGvYWP3QUgwoz0
         DS70SjMyhs3ACLraLEbbPHUcB8pXPAEHvY20haIgp2zuX4VFXgEWD9X5VnoI1piNW0uX
         ychM8FM+J/uLYmvRJuKX6TGJTAa5tfnvQ1It6PZoNlPXF+4ygqBo+2ferCOMqoJ6a74r
         g5gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=S5kJVxPB;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XviR8X6BWscvCw9S/VSnsXo1kyFt/Ons9DuG0IgW66w=;
        b=gMi5csUOrebi7Dn2wqBcG3cBoNa91w4AZDGFikwgm8aQYal7UKQnggsoBuzC9FWtV1
         VxJlMIYPzf/V8kn7MsY7NduFP2EBHre3Vs5qwGOatCL3IvxkgcrPA6T8FoINQ5ZFgmht
         opY/AERU0p6GdvC8moaHMCh/YgE5tc9/t5yCS+ubBCWPFLJ+A8QG+KxT6rm7Kkwt/aDk
         aI9Unf2Z2/tzByO2nZvxGrj2SPAzN8mS6aKJ9sj2lXI60xMuGbA4CWHQeOGxFXOPJFUe
         GZGCLoP8e+P95JNIDKabvsVlCQ0He/lQ5TgHP2nqgTES7w0qraLazGVUqaE2BU/WKaaV
         tJ6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XviR8X6BWscvCw9S/VSnsXo1kyFt/Ons9DuG0IgW66w=;
        b=kHUiUDhSM/mtMQtsBndUrYUEShaXVKYujlLTxNAEB9l19leVEPg2m555ATIjY+ef6H
         D5hy8TbdlmxxHAQHz+HvteG7V+TsBIsgYkoIM+m5o8yw0dyKpacZ/grsJEgbvqRULIfE
         DJeuhxe7w2KPM8zBjVsLEBOEd2yIiCMooJjKYOnLW8A2IuWmaDTRiy2ZEw6BLtf8iiZ4
         6/W93jtSHp/toiL/yLUkXAuON1oW4hNhxEISS5wjUdJy5gGb4SdZMqGUz61UpTf4YU7K
         pYadQ5WvkaBCopGUmv9z8V560ybEQjNL7AqABp6VnWoHu0gbpAgUVDAG1ciw0AsfwSrJ
         E3yg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUkIU8ubYiGgMBI5x+n+Vmg6TQvP67AKoOo6KberiUYNlWazmPF
	nDjP78pOFWoZ5TNd/XLXyKE=
X-Google-Smtp-Source: APXvYqyrLCp2eYPpTXtHAOxcnjXk4nxCsFvkWnvyXAWB0DRilc33Ry0s2rTsjBeIpa3T+8f0soAZaw==
X-Received: by 2002:adf:e2c1:: with SMTP id d1mr3654053wrj.347.1575988777686;
        Tue, 10 Dec 2019 06:39:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb4c:: with SMTP id u12ls6995534wrn.6.gmail; Tue, 10 Dec
 2019 06:39:37 -0800 (PST)
X-Received: by 2002:a5d:5491:: with SMTP id h17mr3830924wrv.374.1575988777158;
        Tue, 10 Dec 2019 06:39:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575988777; cv=none;
        d=google.com; s=arc-20160816;
        b=FR4BJS66xzJjWpwesfT/mKLnqsET6CaH/PKCEpOudQgL/+ApYDIvGDkPymalErgLOu
         qA8EE/XVaWItpsKwaFsNNcfAahY6N3pBnTsO/ycJzY6YY1XzLUOPIb4SECe2lzkl9WDH
         IpKysTUSL0h0gW2K85BKSEklVPlTanoxw/l32BCGtl1ebdExghNzpHdXc/T2X7JynAXu
         nHiR5Mx3dWLiJtPmjx4NC1uLrwzRCO71nZ7eLhdQDVrlS/46sh3+4c3t0Zz7MwEg+uuL
         d0leYgwT01jPPJlhMRNc/HU/34vkscWVnHdYtUd9uTdkZgmJgKWc1UY/3UxTFVeqAZsE
         mgiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=gC07UrkwsOByoVoBIV4uyW1SIFHfck0w0oYmnN2eVmc=;
        b=0s7C74cHzNOfmATkhomVD8+yQJVExckdSX7hmJfK/kATkTQCg6DrMBnCsAlFMJLG3F
         JHKHYlYtO6k0EWwqwU9oSwguu266kB2fVIBKd3p4FR/Dg/cI5sMofEyCALSIQh1v2/Qn
         MeIQpg6WSm1lcl2tmQZk4Hj4SI4RoWHgWQMjE73Qbs6mJWIf+PkOKU56cvSUG/+X3FF1
         D3RsJHcKdlntqZvHceXd+D9gdAVUDYyPgwSgg6aFBz/qsMdBDQuQDHjB4zDQJ4QOEZdz
         rPw8zRAa7NZHC5e8g76wkKRRy4eDsnViC/dDDHDF14y0ChQjNfuhFJ4j94Yn/sA6iCE+
         Lklw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=S5kJVxPB;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id 12si153285wmj.1.2019.12.10.06.39.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Dec 2019 06:39:37 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47XN4R2jvMz9txPV;
	Tue, 10 Dec 2019 15:39:35 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id h_8fAE0U-HoN; Tue, 10 Dec 2019 15:39:35 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47XN4R1Whkz9txPQ;
	Tue, 10 Dec 2019 15:39:35 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id A165C8B815;
	Tue, 10 Dec 2019 15:39:36 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Hn7oLwJSlDri; Tue, 10 Dec 2019 15:39:36 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 96E4F8B754;
	Tue, 10 Dec 2019 15:39:35 +0100 (CET)
Subject: Re: [PATCH v2 2/4] kasan: use MAX_PTRS_PER_* for early shadow
To: Balbir Singh <bsingharora@gmail.com>, Daniel Axtens <dja@axtens.net>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
 linux-xtensa@linux-xtensa.org, linux-arch@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
 aneesh.kumar@linux.ibm.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-3-dja@axtens.net>
 <a31459ee-2019-2f7b-0dc1-235374579508@gmail.com>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <5d1ec6e3-777e-9f23-ea8f-50361a29302f@c-s.fr>
Date: Tue, 10 Dec 2019 15:39:34 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <a31459ee-2019-2f7b-0dc1-235374579508@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=S5kJVxPB;       spf=pass (google.com:
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



Le 10/12/2019 =C3=A0 10:36, Balbir Singh a =C3=A9crit=C2=A0:
>=20
>=20
> On 10/12/19 3:47 pm, Daniel Axtens wrote:
>> This helps with powerpc support, and should have no effect on
>> anything else.
>>
>> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>=20
> If you follow the recommendations by Christophe and I, you don't need thi=
s patch

I guess you mean Patch 1 (the one adding the const to all arches) is not=20
needed. Of course this one (Patch 2) is needed as it is the one that=20
changes kasan.h to use const table size instead of impossible variable=20
table size.

And that would also fix the problem reported by the kbuild test robot.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5d1ec6e3-777e-9f23-ea8f-50361a29302f%40c-s.fr.
