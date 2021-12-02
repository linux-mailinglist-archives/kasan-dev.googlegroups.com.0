Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBU7WUKGQMGQEVQUL4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C62D44663A0
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 13:25:55 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id c40-20020a05651223a800b004018e2f2512sf11183044lfv.11
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 04:25:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638447955; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0K3dL2vobF3+etmX1CXG1zIYyWY0QGawjDwltsR73ymbhjV9LdogFlpSp1Jn8vHbz
         1wrFJyNFv/xdDcbKujC0sbHv3dPm0wuxM0uxIAPalKog9ZjMVEuiNf2EX3sQSNRbtI/y
         Tf0o+b5MPFKwg0n8l+w7/HeQ0sXX5Tpkrd7Ho0R8IHX3VIFxCx+QXeQUxYLdAoSItrbn
         0zGa7zz2KKSnxmCKobgfjdSCbesm4TWK4lKSn3scA+m1tL2iPWB1D6qHFx+oztj8IDqh
         hjir+kIvhsrKox82qgoaiRio8FxQ+KcTyHkf4l9Vacc3soMA6SLH8vj27igZ6F+s7fZu
         lXnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=g/iVXTWvHiy4nVqoSqQv1r67oRnfnVAgXn4PTitXt7g=;
        b=w9nQcUPms03gGgSPsJThx52c2GAZFZeOVFINJh8KqCp8YhkGRDdh/nFh3IdtJXlqYe
         X/nZi1g5hEKWTbKo3Bt4hN8xF8hJGr7dup1iH8mew9AyHhPMf+7ZXsu9cZtguTucGdtf
         6CYP4eHf4xmNNzf4j/Kwm9o+v4o3tlMW5W3L7GGUS613WnAI9uFdjflEnV0VcDWblmXq
         RrDno++XxJ0BRnXNdKoKVM3MsUhw9CY9k7uBgLR4AxzS7IVGVoRapK3dJEfTkrMtGmTG
         bKbf5fDQZYrKqr+tGAFonr3muTyw0AzewUa3HoUxQUGObrah8AM/F/BIbm5ESvxBOgPS
         KkfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qAgWGsgs;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g/iVXTWvHiy4nVqoSqQv1r67oRnfnVAgXn4PTitXt7g=;
        b=mxRFVAwdVRyLJissWQOtsbQ4wGIDmcUVED3gt7bYe1LCX+9jtupyxYc6caxrzrlfNW
         VkiyEl8pn6A2iPHXwWkocoigGs2NmviHAq6xX/ICsazmX2QARqcCp6HXa4IG8nUk7hhM
         kpOCmg3PnPElJcyVSXb8C5OK8qSha9ZHBcUC9lzeNtLpZQg+ukbahh8coZ1NCsslIM3W
         tyDZ6UAVT0yg3NSK18/HyCnynvrcmhjsTqU54F0j+VG+wTb2k2xx7zO6bNUPjkuQWPGL
         xDjSn1YhpBr8ievEsoXxWa6ROVJZmpikeYaXwDiRoO+AQmCyH2f9MftSexz6eX5YtIHp
         rAtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g/iVXTWvHiy4nVqoSqQv1r67oRnfnVAgXn4PTitXt7g=;
        b=YDQr+OCdq/3hBZKcaQQkgz6PhwKN/5EQwdHlg1k2OXmxksHIwFk8jHatkuLn+StiGd
         9VJSkOl7Dl1R1rvJ6bCtkZeInTrRWiGJkts/y3NpJzron4BsQDamRSreT2oczUWUAE2J
         +M1Iq16w/sGhfWrQeHZrcpbEZb81UC8P0Z1z++6pRMU65PzMHg/orx4Fsk+DLCzXUhj5
         xmC339XC6Ej6xvoF8i1Lu65ge/BZpgpKtN/XULHfQ+fGcRe+3pa+5az880xWz4T2MmSA
         L3aPJleiMlJOY+W0MKXSdps+dgOU/yzZaq0NGoprF/o53KgChb/Kn+fs4PWqYVFm3EV9
         Z09A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532fWd6QVCMot25BewDOO4QZVdHrOyuoS+xiC36ew48ktbHdqqMD
	Fk5yFnRqlonuuZZ8X7stfvQ=
X-Google-Smtp-Source: ABdhPJwztIj+vKmCWPTqzHaHzuwmls+ao34AS/1a+1GxyLc1RYZKdeAIoXccbEYuF7uYJeciYKm9xQ==
X-Received: by 2002:a2e:a7cb:: with SMTP id x11mr11904471ljp.308.1638447955273;
        Thu, 02 Dec 2021 04:25:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4c2:: with SMTP id p2ls969504ljm.4.gmail; Thu, 02 Dec
 2021 04:25:54 -0800 (PST)
X-Received: by 2002:a2e:86cb:: with SMTP id n11mr11829062ljj.425.1638447954203;
        Thu, 02 Dec 2021 04:25:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638447954; cv=none;
        d=google.com; s=arc-20160816;
        b=rIEBXcLedo7uVbJyyZ0ekd6+P28yfNPmmn+cB1Y/cuyj/npziKFG1RVmZGn1W6nfJ2
         ywv5WFvgxZ3iEFLGh5EuD7ULe88cqNC6Zh0frY78BFRF71neYco3bNK1rW5XE1e26oU/
         h5cWsQSoRHnIts2I+yEc0yk3aA0+UChocFckEKD//sYqheziyVLGVccBW9m7bWe1Fhwl
         BCseiLTl7E76bGOE4TPD6Z8v+mI2TB04lTx4ikj/oFechJB974sbUo71Bt6uIFgLOhaz
         xo/SYHL/LNpS9q4MlibaPIEFU8WtNbltcpo6Gu24a6NxLEwymj3bMVh46FUtSeevkJUL
         ZhxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=MrIx4FxLZ15vBR8OhFRI6NkqolHxOQGKVsTXFgnLCBo=;
        b=0mvcSbYO+t/0O2yq4OgP//nr+0p8SkVyFsrr1lurCBNqGJeXriUjwQfmdDN8WpK5+o
         rJQpyyeIAUeesRHOic9s43HqITXdA6AIciDMPPV5OcTwBOAR+gWssFLtKzO6qRakGWQb
         tkrDP1tGyriX4rXu4XLo2LH9JndGzT06cwVWhAr9ct+CV46DuctAvLRx/xtysnXznFpb
         vwp8DH9Bg5DBKOPj0eMcIHfUjbnjFKXxtnDG5vRD4HEoQ9EDNlcULxz3rNUS1p/81crW
         LosvRBANkRbP1MZWaqGwOX4zOUzLcbHgfRSnCAA4K8BFPkDulIbLZ69a8XLWiU3c4+YH
         g4bA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qAgWGsgs;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id i12si221919lfr.7.2021.12.02.04.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Dec 2021 04:25:54 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6D466212B9;
	Thu,  2 Dec 2021 12:25:53 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id C2F1313D73;
	Thu,  2 Dec 2021 12:25:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id RdqfLlC7qGEUIAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 02 Dec 2021 12:25:52 +0000
Message-ID: <3fb4f879-c48b-7f74-c7bd-59ca16c5fe8d@suse.cz>
Date: Thu, 2 Dec 2021 13:25:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Content-Language: en-US
To: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org, Andrew Morton <akpm@linux-foundation.org>,
 patches@lists.linux.dev, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andy Lutomirski <luto@kernel.org>,
 Borislav Petkov <bp@alien8.de>, cgroups@vger.kernel.org,
 Dave Hansen <dave.hansen@linux.intel.com>,
 David Woodhouse <dwmw2@infradead.org>, Dmitry Vyukov <dvyukov@google.com>,
 "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
 iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
 Johannes Weiner <hannes@cmpxchg.org>, Julia Lawall <julia.lawall@inria.fr>,
 kasan-dev@googlegroups.com, Lu Baolu <baolu.lu@linux.intel.com>,
 Luis Chamberlain <mcgrof@kernel.org>, Marco Elver <elver@google.com>,
 Michal Hocko <mhocko@kernel.org>, Minchan Kim <minchan@kernel.org>,
 Nitin Gupta <ngupta@vflare.org>, Peter Zijlstra <peterz@infradead.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
 Thomas Gleixner <tglx@linutronix.de>,
 Vladimir Davydov <vdavydov.dev@gmail.com>, Will Deacon <will@kernel.org>,
 x86@kernel.org, Robin Murphy <robin.murphy@arm.com>
References: <20211201181510.18784-1-vbabka@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
In-Reply-To: <20211201181510.18784-1-vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qAgWGsgs;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/1/21 19:14, Vlastimil Babka wrote:
> Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> this cover letter.
> 
> Series also available in git, based on 5.16-rc3:
> https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2

I have pushed a v3, but not going to resent immediately to avoid unnecessary
spamming, the differences is just that some patches are removed and other
reordered, so the current v2 posting should be still sufficient for on-list
review:

https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v3r1

patch 29/33 iommu: Use put_pages_list
- removed as this version is broken and Robin Murphy has meanwhile
incorporated it partially to his series:
https://lore.kernel.org/lkml/cover.1637671820.git.robin.murphy@arm.com/

patch 30/33 mm: Remove slab from struct page
- removed and postponed for later as this can be only be applied after the
iommu use of page.freelist is resolved

patch 27/33 zsmalloc: Stop using slab fields in struct page
patch 28/33 bootmem: Use page->index instead of page->freelist
- moved towards the end of series, to further separate the part that adjusts
non-slab users of slab fields towards removing those fields from struct page.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3fb4f879-c48b-7f74-c7bd-59ca16c5fe8d%40suse.cz.
