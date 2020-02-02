Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB2HD3LYQKGQEHMIGHAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8684B14FCDC
	for <lists+kasan-dev@lfdr.de>; Sun,  2 Feb 2020 12:26:33 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id t126sf3862612vkg.6
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Feb 2020 03:26:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580642792; cv=pass;
        d=google.com; s=arc-20160816;
        b=qPNIjB1OU0crzh2Z4Yhm7rDBh7YqlYgVRKwPPMq+AnZNIAR1m7l8kEsjsdG7QzC9SV
         C7U0TwOtDzYB+SfQgJlrcd75N0AinjDavVbmEl8D/5R9V3zeZ6qps1dGUdfvJrZxnLYM
         TxNTlqo+U9bqvwKPbbQymuDAjOXzvOorSFdEL24VX0zLURR/DeG9sh0UIcWUCMAxuuPz
         rfO6ZXn0yzyn6LopwGSXl5R0NRoWgyTmnWhaFrvGtnMf3xMRYM1ZP/nf44DU+Y57WHLK
         WfiM+Z9sVFwJsiPnK0xY9VUMr2/e5dJTgGzkssdbg5MdXQ4VWVj+gxRkMkA6zQJ/6aCb
         PaTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=wl+YjVXdVgnMTcqJG/EDhUXIOWE1QyX1Bs8NKk4vZcs=;
        b=esDWJRi/DrSZnopwYW8dq43H8x87FxEL34LidNGjOMw35v7Y2VWhB44ngpwpd6DuF6
         s7wrtv5eTCl1W0s7ip5PHFTh4m4FEJJc8Zt0+75fUWpcMfk7w7Q4y49zQ1kHL+zMjsbK
         Z3kJbn2zsfa46qfE8r3KS32amFij/jrI9t8W098UecvfBmps6VC2/U1lCR82QxAI4Cn5
         BQPSVsD9hLGqPbNOcFiuJpGLDdG5P5sFH0tJUZs5Jj38HLkyfP8QIYZWhx7Xs110Uf3D
         eN6bl0LtsMyEh5+ijfL6TKRSaEH/ayDvCH4HPG73GEKwKhi8m5yz3fxiUdfsK1V9zCCD
         oh0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ktqi1Si5;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wl+YjVXdVgnMTcqJG/EDhUXIOWE1QyX1Bs8NKk4vZcs=;
        b=JovBiGEKnBOG0z1OHxHUf666ukc5GsaetsFBjW99XbFLC6OYzFG3O0m5xIJP3WjpxW
         0SOlLaCz9LC5ev7k7J69Rx62NMN2ahqGT+urZ7xl+aX4JsVkSxM5sna3nnJR+n/eJMhx
         kQ/JSHk50r/B9EvDFa5nR60NSJV0+DV/Ge6TD+Z7kHwVAnTJ68dktLm1XDQ5DEoQG3go
         z3BBKeuIq2pquHN1IBY6EmlTK29ihzdlmrOJpMO/7KXM2P5SbA3UkCgl1CNhqsf6ePVp
         iLWkhtBdYp8nnGRtq7d07QKGIi8mau4qk1yy+KeeerpNt1V2cD/6MXSAusmuKyjvPyp0
         XsxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wl+YjVXdVgnMTcqJG/EDhUXIOWE1QyX1Bs8NKk4vZcs=;
        b=fJ236kINHjGmCIURKFosCALttUYLKwfOEeipQt/J2FAljesmg+mXQ5D5DYSvcpE6S0
         /v4ewoJgkB9N0rtnyuUaXFWtZm49FJWb3FM7p8d6RKsi8vJ4J1A29MO2vkZ9UQI6niw9
         nKPCIQEv10hONVdDFeLxwibabt1uDarQOdhIiovHKSL1SOZFQT0Z/1DD/aZsspwVUEWx
         OD3K7Qs9pgduqokx4wyKGK5urtBAFFJFNLPZVX9S76H+geYcLQmTUS/0XVbsfuw04fvN
         Ik2HjWVq5QDGdr4ZOHIqPFCazR/E9A8M9UdTrYi1XhAZceNvpJKBPdkwohZyAPcIi+vR
         xeEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUaERFLHv+Ga0zf1rhLbImHDIv1PeDKGx9cxXJHCyefKbQlQHX+
	ykqS9SUJhKxaqvE5DvH3O9o=
X-Google-Smtp-Source: APXvYqyqA3MHCazhg36nAI1DpPfZVJ7r7wrlayTO3xsI58F039ud2m6vHs3oU0ZumP69uuBmT6xf0Q==
X-Received: by 2002:a67:7fd3:: with SMTP id a202mr12285233vsd.1.1580642792592;
        Sun, 02 Feb 2020 03:26:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4196:: with SMTP id o144ls600248vka.0.gmail; Sun, 02 Feb
 2020 03:26:32 -0800 (PST)
X-Received: by 2002:a05:6122:1065:: with SMTP id k5mr11242227vko.14.1580642792114;
        Sun, 02 Feb 2020 03:26:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580642792; cv=none;
        d=google.com; s=arc-20160816;
        b=z/M8NHVYCeBeZQLz0Aq+5gwI+7Yhg+sDdwezGFpSE6gF++xNqYe8RFW+OfO99pBF5w
         haDrGOzDMruIhQYcmH4CBKv6yiwNGvbMx/V1xidHUNhrW3I20pfhkjtgHlg9MohNhxnQ
         98i3ekTmRn315R4rilEr+miA7uNFUIuV4ncAg8Vzmi4HBtxDMmjf8hljE2qI0ETv/sZH
         TTUZ2AHii9OUsy4SMWcI2A91Wa6HSXGvBsgp+CJAtinfi1VUrph9TPZ34gEYhK4PxJbQ
         uwvFx0Eai7JRuFN68wxQco3Nkyd9B/1JlZzKWpX8sVxicGwBiSE70zJ0UwsY0joWMRuQ
         xPDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=haUAAZdbmdU3COyJ/sqnDbNti6tUXhiH5WpEb5CUu3o=;
        b=nxM8fmLQPJCybD5t07gg8rC2uDVejiGnM+7bIwVKj8JKQIroBlXLIQUD+rhmZFo0Zb
         ztmIiYDeoM98WEX2QGxVFEi15sKJyaggKmqX/81Z65XuUb7ah1v1u1uAMaCghJokYoLX
         5InGAXL21TXzlrOflvha/jmMJZprk6GKT9rl50cZnhb0j4dC/Y3Ps8THrtYW27b4dBGd
         JeLhJHGaZWybyu0p4jw1JK3pAlo9gx54c8sy2vdcJVSJj2wS+zlIR//eD52bGSXnB3uX
         jnA9992h8mp9JtJM7OfV36BmfSncts8DfzjddWTpYbBNLehJu1LYPl0tMpbC3aQ9s9HP
         qYQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ktqi1Si5;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id h7si581314vsm.1.2020.02.02.03.26.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 02 Feb 2020 03:26:32 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id q15so11399629qke.9
        for <kasan-dev@googlegroups.com>; Sun, 02 Feb 2020 03:26:31 -0800 (PST)
X-Received: by 2002:a05:620a:218d:: with SMTP id g13mr19497581qka.286.1580642791619;
        Sun, 02 Feb 2020 03:26:31 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id s1sm7274932qkm.84.2020.02.02.03.26.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 02 Feb 2020 03:26:30 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH V12] mm/debug: Add tests validating architecture page table helpers
Date: Sun, 2 Feb 2020 06:26:29 -0500
Message-Id: <2C4ADFAE-7BB4-42B7-8F54-F036EA7A4316@lca.pw>
References: <473d8198-3ac4-af3b-e2ec-c0698a3565d3@c-s.fr>
Cc: Anshuman Khandual <Anshuman.Khandual@arm.com>, linux-mm@kvack.org,
 Andrew Morton <akpm@linux-foundation.org>,
 Vlastimil Babka <vbabka@suse.cz>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Thomas Gleixner <tglx@linutronix.de>,
 Mike Rapoport <rppt@linux.vnet.ibm.com>, Jason Gunthorpe <jgg@ziepe.ca>,
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
 "David S. Miller" <davem@davemloft.net>,
 Vineet Gupta <vgupta@synopsys.com>, James Hogan <jhogan@kernel.org>,
 Paul Burton <paul.burton@mips.com>, Ralf Baechle <ralf@linux-mips.org>,
 "Kirill A . Shutemov" <kirill@shutemov.name>,
 Gerald Schaefer <gerald.schaefer@de.ibm.com>,
 Ingo Molnar <mingo@kernel.org>, linux-snps-arc@lists.infradead.org,
 linux-mips@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 linux-ia64@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org, x86@kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <473d8198-3ac4-af3b-e2ec-c0698a3565d3@c-s.fr>
To: Christophe Leroy <christophe.leroy@c-s.fr>
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=ktqi1Si5;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Jan 30, 2020, at 9:13 AM, Christophe Leroy <christophe.leroy@c-s.fr> wrote:
> 
> config DEBUG_VM_PGTABLE
>    bool "Debug arch page table for semantics compliance" if ARCH_HAS_DEBUG_VM_PGTABLE || EXPERT
>    depends on MMU
>    default 'n' if !ARCH_HAS_DEBUG_VM_PGTABLE
>    default 'y' if DEBUG_VM

Does it really necessary to potentially force all bots to run this? Syzbot, kernel test robot etc? Does it ever pay off for all their machine times there?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2C4ADFAE-7BB4-42B7-8F54-F036EA7A4316%40lca.pw.
