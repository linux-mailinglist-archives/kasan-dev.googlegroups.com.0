Return-Path: <kasan-dev+bncBCXLBLOA7IGBBU7R4DYQKGQEI36XIFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 14E8A150968
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Feb 2020 16:14:28 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id t11sf4083429ljo.13
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Feb 2020 07:14:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580742867; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIMxBi5mpqKb5dnojWVbl6ZVkJVZ+sJQgOUolzabq+Vle4oP1sK3Eid3ljwH4+MUIZ
         UEOko+yYuYwd4CUyG27hANvPVysr0k9OKb+IENrBUK+jQZcWuKr6gkR5l9RF1OunDc4M
         4CrO172SydyNBczwE50NQ92FHMIYQCQPe1KlEbrcbpuqi6ACsZkr+xiPZAAmmjqV9ESq
         shW4QnqgQSdqyGX7JPqnXu/A0ixgR4VF53Qy2qz7vrWR8gAvnvgUKVQO0B5HaY6PDMTt
         zKAv80uLcnEMOCxxbL9RDnGKh07NhR+3u6g915hzmM+uq8H/ouuSPLqfJbZU3VC6Uht7
         2X5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=sh/SavcTOmhG5+ECtOqrRlr1Sj2OP1hpY1csAgldN8A=;
        b=epHMT/KY5YDcC9OCt+3f9qYIiDFaMKfd8tNwRkNc/MoeDFE6untQ0t6W7CXGxUUbSg
         lzvO96pHXJArzmAeZo52PAikp1F0vFSWIt7xZyqAx+zToF1WLiZy7CYs2Hs49kdmORWW
         5q8QZ4Hj67IYT9zciWMup5wOYL0bYAAB+PpwDORceNedbYdxMV5yRNuciZtMlV7Ke75n
         6udh2N8S04LEs6b0dY0RH/wnDBRBgp+nmh6RfI7Trt6biNn+mm2KMX0r50Nxa3u5YmiM
         cjLmghUTmxDeAWPLZ2XD0Fvd0zNLXl4OEbES1dGCsYu3mBbUQmcROnZ4TOF69jnb0O2t
         ZMfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=OGtzFIa+;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sh/SavcTOmhG5+ECtOqrRlr1Sj2OP1hpY1csAgldN8A=;
        b=oUi6nDhTkF56yx1fWfmdreSgRTcOq6+7SwbCDp35NOuDhAaCX59POr/HAJTqc+mNRK
         5lGmbRszOUA7l0jr90QM54Z5b0hfYlWTm/5wOwx1mESthDAtn6icw991jJk6eDs4l9LS
         rCznI/VEgVajmzUrBzMBILk65DHEeEaCpEOKfO58IIZ0PGpoyj5NjUwBCpym06MEdhf1
         wRSrNwVteuueM3TFfl13s9evLBfAVtaw/nKCx1kr/sA+Fdp108Dv9RLHjRhsvxHx8xBt
         OFK0lu+O6RuMd0lGuDeiLIddWTgVFItTKGX8kBTTfp5mC/k4NPJevVrYiEyJZ3bi4UlV
         NCTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sh/SavcTOmhG5+ECtOqrRlr1Sj2OP1hpY1csAgldN8A=;
        b=brdCsme0S5xZNWkp4IOJ9mYDU6eJ+g+ZMJKjbBfrwR/AOhDAPzF9LXmJmnPFFKTDTZ
         tz6owlEQzTxooPgDdxaX6ItsvAXibRSzEKjCEPcV3G5bruvSL/mQFRIJmYu/46MVrIQx
         yPC5j7uiB/yo24crvkqJ0TDBHMej/Rpt0msy+B8b/RB5Pzl2UxaDqDgXQvQwcZXyr84m
         uK8FAmtv7JZpfp4Ikp1xCtJZbBFKxZgrJxg7ifMpmrfnBC/mSAd2u6lQ+KKBlQ9lv27d
         qNlQqEq1TnmDBzlPnUCKThemgAUuMGewAaEQAMzHFQQZScrPP0n2E1FxfuT3GtI4IZIx
         1sqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVFhtyhYoTyvdioRf6RWs3zmkvtmbpnTYLmmcnu76u/9YvVw8ZT
	cmIG9qYKRsHvgw5/WGKERXs=
X-Google-Smtp-Source: APXvYqy6kfulLYcu3ZNM1hcTIZ2JQPYzpzOHwSNUfn7rNa9IV4YFxMDLm3SMo9RMamZ08V6bouxWtQ==
X-Received: by 2002:a2e:e12:: with SMTP id 18mr14451731ljo.123.1580742867377;
        Mon, 03 Feb 2020 07:14:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:8488:: with SMTP id g130ls1069567lfd.11.gmail; Mon, 03
 Feb 2020 07:14:26 -0800 (PST)
X-Received: by 2002:ac2:52a2:: with SMTP id r2mr12153235lfm.33.1580742866736;
        Mon, 03 Feb 2020 07:14:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580742866; cv=none;
        d=google.com; s=arc-20160816;
        b=zfhRnb0r+D2rdMK3I5JtDjkCb39VVuXNodmuQQOteI2ki+YhZBch44YVq095ET+w0E
         pYGdXmdUfc9BDVMvGMApaK9O8Ad9TN4aL8dTCzkJOWiUlPtzTz4x9xUGznl8r1mLszst
         NYCLSMCLmlwmgN1RaWbDA/H6omrrslyE21puSw9DONZ/ALDf3ccNbx10a9Mrt8F7XChE
         Myfm+5wzichMlJB8/ANtUe7/sbGeule+BQob2ESWfpdY8a6WP5Xf2NQYqSqCvo2lF4y6
         Ycil8EqJ20xazAeNPjcd+ohvv9Voy83lWlD7GUgOs3VDPSImgnnXDRTOgnPBV4QQyMt1
         iCEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=i4hAG7YwdO6LNDmYZ4wBEtikutj9N76WG5xl/PwnPrw=;
        b=0RuqqtAfVYgzzTSVSiIQZzaoUsZLOQvNBuvCAaUWt72blrbQtzW5hWYHBfSkDicXP8
         nUOBSpU3Lg2uwm76eDeo27Wna93ii0NG/eG7zVcGnu3vUUiio5M08pF2Bhggeo8c4z3V
         aFHn5JfdImd+3U1rs16WRaZtP5/n/cWvwlRR18wR4HfCWIoIGKSSo5aXtyxyV92S2n3K
         80261jxkRDdz94XyxNLLQy1TT4DOlxgXKaFy9T7NJXGo1+yKXoN8hrWVWwvQG9QorRM9
         BmHts01s3/4ZYLPybZYX7fsAqP0Oo7/3X/fZDkI00eL6ine+zoRiHMolaLYyqrnuxx4l
         0ZDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=OGtzFIa+;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id e3si869791ljg.2.2020.02.03.07.14.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Feb 2020 07:14:26 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 48BBF846fMz9v3ls;
	Mon,  3 Feb 2020 16:14:20 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 5VszB6UW2Yif; Mon,  3 Feb 2020 16:14:20 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 48BBF82h8pz9v3lm;
	Mon,  3 Feb 2020 16:14:20 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 7DE228B7B0;
	Mon,  3 Feb 2020 16:14:25 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id unrhNEULKrXy; Mon,  3 Feb 2020 16:14:25 +0100 (CET)
Received: from [172.25.230.102] (po15451.idsi0.si.c-s.fr [172.25.230.102])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 12E638B7AC;
	Mon,  3 Feb 2020 16:14:25 +0100 (CET)
Subject: Re: [PATCH V12] mm/debug: Add tests validating architecture page
 table helpers
To: Qian Cai <cai@lca.pw>
Cc: Anshuman Khandual <Anshuman.Khandual@arm.com>, linux-mm@kvack.org,
 Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Thomas Gleixner <tglx@linutronix.de>, Mike Rapoport
 <rppt@linux.vnet.ibm.com>, Jason Gunthorpe <jgg@ziepe.ca>,
 Dan Williams <dan.j.williams@intel.com>,
 Peter Zijlstra <peterz@infradead.org>, Michal Hocko <mhocko@kernel.org>,
 Mark Rutland <Mark.Rutland@arm.com>, Mark Brown <broonie@kernel.org>,
 Steven Price <Steven.Price@arm.com>,
 Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 Masahiro Yamada <yamada.masahiro@socionext.com>,
 Kees Cook <keescook@chromium.org>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Matthew Wilcox <willy@infradead.org>,
 Sri Krishna chowdary <schowdary@nvidia.com>,
 Dave Hansen <dave.hansen@intel.com>,
 Russell King - ARM Linux <linux@armlinux.org.uk>,
 Michael Ellerman <mpe@ellerman.id.au>, Paul Mackerras <paulus@samba.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Heiko Carstens <heiko.carstens@de.ibm.com>,
 "David S. Miller" <davem@davemloft.net>, Vineet Gupta <vgupta@synopsys.com>,
 James Hogan <jhogan@kernel.org>, Paul Burton <paul.burton@mips.com>,
 Ralf Baechle <ralf@linux-mips.org>,
 "Kirill A . Shutemov" <kirill@shutemov.name>,
 Gerald Schaefer <gerald.schaefer@de.ibm.com>, Ingo Molnar
 <mingo@kernel.org>, linux-snps-arc@lists.infradead.org,
 linux-mips@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 linux-ia64@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org, x86@kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <473d8198-3ac4-af3b-e2ec-c0698a3565d3@c-s.fr>
 <2C4ADFAE-7BB4-42B7-8F54-F036EA7A4316@lca.pw>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <8e94a073-4045-89aa-6a3b-24847ad7c858@c-s.fr>
Date: Mon, 3 Feb 2020 16:14:24 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.2
MIME-Version: 1.0
In-Reply-To: <2C4ADFAE-7BB4-42B7-8F54-F036EA7A4316@lca.pw>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=OGtzFIa+;       spf=pass (google.com:
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



Le 02/02/2020 =C3=A0 12:26, Qian Cai a =C3=A9crit=C2=A0:
>=20
>=20
>> On Jan 30, 2020, at 9:13 AM, Christophe Leroy <christophe.leroy@c-s.fr> =
wrote:
>>
>> config DEBUG_VM_PGTABLE
>>     bool "Debug arch page table for semantics compliance" if ARCH_HAS_DE=
BUG_VM_PGTABLE || EXPERT
>>     depends on MMU
>>     default 'n' if !ARCH_HAS_DEBUG_VM_PGTABLE
>>     default 'y' if DEBUG_VM
>=20
> Does it really necessary to potentially force all bots to run this? Syzbo=
t, kernel test robot etc? Does it ever pay off for all their machine times =
there?
>=20

Machine time ?

On a 32 bits powerpc running at 132 MHz, the tests takes less than 10ms.=20
Is it worth taking the risk of not detecting faults by not selecting it=20
by default ?

[    5.656916] debug_vm_pgtable: debug_vm_pgtable: Validating=20
architecture page table helpers
[    5.665661] debug_vm_pgtable: debug_vm_pgtable: Validated=20
architecture page table helpers

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8e94a073-4045-89aa-6a3b-24847ad7c858%40c-s.fr.
