Return-Path: <kasan-dev+bncBC7OD3FKWUERBSXSX3FQMGQELKQ3LZY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +DUpJk65b2kOMQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBSXSX3FQMGQELKQ3LZY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:20:14 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D7CB48743
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:20:14 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-8ba026720eesf1615220385a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:20:13 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768929613; cv=pass;
        d=google.com; s=arc-20240605;
        b=O/Kccui81hOUA10gqyiWu+hwKmytyXab2kvRYjt2FrR73E6MlC9VEunQttKLaq24vL
         42MYyMFsRvdIBxlekXAd7VH7nLJ60HzyuIWWH/rJs9Vix3jAkdzF6JiAepjc9RvUuEq2
         sidOxjonFlRkfLZQAABDPkzJHzjqj5w8Sb2SNMpL4Prk4nH8KrHSEUqWZSV3bm78Vs7s
         KPVXpUHKRv2xwrPJLhxkfHBErBTW5ZKqamxaZDOuG1KmqeUxIX5lBCNz1kkU2oBojk8X
         S7kHyMxazDY27b0GI7ZQaSdq3Tv9qZEl0l3hzZdaINkLylgMt3SGn9OATXMvaMAwUh/t
         PoOg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+N92Jt57wtB3rH2J4Z8Ah6ezL0+q3WGMDMtOUrJcYwY=;
        fh=R7xeRbW1Y3kGqlN2wW+u+1qOD8IityjIt7eCXc/qz58=;
        b=SlNPcXNCanTGM38bY6cCNo4apc176jyLvYtdFuV65bROvrcf4qjkIABPfDSzguOSYr
         LRZ+AtkLLl6i42mJmoNSGswbsR3+WFVvlpaPe2tMGN3u1Xny+yUPlTqyIEh+gSpCy/rW
         FkiW7MVv8IvNrwQCqDbkK/yg5vd4b+Xh7XJKNGNYEf6RImIV1O8WvL/a4fZMin2PMwkn
         V4D6wQEO21BL0c/RXJnNNAgvp5pTCrePjLter4ew0Yk23fpK2v+0s3Rud7GfAkHQGX5s
         ZelY9WfTmd0QAB/FqENuweXZjfwuflk8a0NuFDfCucJTMsUYHiRVhQWaDcwKwaXNJzhh
         +TzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oO4La249;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768929613; x=1769534413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+N92Jt57wtB3rH2J4Z8Ah6ezL0+q3WGMDMtOUrJcYwY=;
        b=jUgyOwCwNLyqtefO/79Xa5WzQqGTukN5JKw9yCTodjxHY9ScChO9A6o+ICC2XkASZx
         qZz8rfpSTCGUOAtYUwM1SOhBVduBWy2cuC73RRZUi7bJkkwIRaGR07ory22VXFkAlK0i
         ZL38HcyRrlHPFsofFtoLyxykvFtX8eGuGXUVwKoz4ObATAzFXS0dlCe6jeBAHXMM6wCe
         GLAvjxcWZHaiGNakG3e32ECHxUaJiSAyb3nnuXARTqbE+jje2Sde370VUEe3uX7Cmzec
         QmK6kSZjr8gqSsmRsNRafKiWd/3xrBaiLC0FojBFVdOp06hkLJ3WNPgC94o9NhcdMCJH
         qBLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768929613; x=1769534413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+N92Jt57wtB3rH2J4Z8Ah6ezL0+q3WGMDMtOUrJcYwY=;
        b=w0/DncnXxbRX2vHmKHXk48GdE0Muu98oKJMv+ObsCm2fX+iuomf5BnG3FJOW7TsW3b
         Twv+VPq5C50m/b/Mxj9oOKI/EcXFKQwhruk+MKk5UDsY5uPM7/GCTtgzEijaaz+yckf5
         zyUyHtrQMZltSFG94zEpFRbSra1W2hQFz89EV5HpGzKgX5UsMk8iaYECsfVI1uXp2xDR
         COJQ6s2SWtUd9megsDq5N6NgHmmPvSPSPmm5SWgCk0nlIFyJnYMAKbsiY4gms6KEr213
         Ft+z7DbMAJr/2HtYSWAJV4EtpCGF84hdYRapuoVWMS6hTkokgGyTI6G/RVHi5pHpjpL7
         Lb/w==
X-Forwarded-Encrypted: i=3; AJvYcCVUjz4ZZpGKmzmLGxBMmHq551tKsTYuPR//sZOzX7V2vdIvmUsDDUm2tZkRJfWC70y3Kpj+WA==@lfdr.de
X-Gm-Message-State: AOJu0Yx9QaSRgoFLK/CG0S72cUICDZo+mzjc/062nBuLd90Gh4FDBJ9L
	+5hb7c2pJY4XnY4BeVpyAOc71hnXZ0mJTqPNQq2edwKCvKy2f0UXPFFZ
X-Received: by 2002:a05:620a:1a1d:b0:8b2:e5da:d316 with SMTP id af79cd13be357-8c6a67a4241mr2072161585a.87.1768929611157;
        Tue, 20 Jan 2026 09:20:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EmI2VdCa/vH5uMVCe7dQXIGlObCb4Y1NeUlZRQ7BRrSg=="
Received: by 2002:ac8:7f4f:0:b0:501:51fc:c16f with SMTP id d75a77b69052e-50200b1378els86772841cf.0.-pod-prod-03-us;
 Tue, 20 Jan 2026 09:20:09 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXJIsrgM6vgEDeeecNrbXpg+NDbh1WmOD0pXwudjoDKq9u+tZCXb4fMEBNR7PAS13MnJP+Xbnf/sQ4=@googlegroups.com
X-Received: by 2002:a05:622a:1649:b0:4ed:b94c:774a with SMTP id d75a77b69052e-502a1648dbemr233518501cf.5.1768929608743;
        Tue, 20 Jan 2026 09:20:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768929608; cv=pass;
        d=google.com; s=arc-20240605;
        b=HjwoyX18Vl6MHpmn3V2lG4CFnjv68iWFtUtQEphdjUqsJjJ54sVml5ledNYJHZoogm
         1iGqrJj9nDHR2WDFlHxo3TkhuwacZqSddBqazJaoN4k6Hky4EjWqxzihobAxB7tJ6HA6
         u02nuycNQ2jQRnvvUSLZd2kvxKxmlhGa6Pkw+DK5gYBlv0zUCG3ZxmdpsU2kOrTvl4Pt
         A1Tg3tshTOFfi4D8kZ+aXkDJ9BOp/u+kQmdgP0mhcUGVw/SalIrGMeXGlCDjMSIgtx2H
         RONYQ+VfZqv5i2rNLZcK1qwQkCpGu9hG8J4EJF5bkHfNwIbU36f3f/sVEXhhq/EHjE9t
         alTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XjgInJxzHZA1FL2RVNq/kScJMYVHdTMpDmOcyNlB2Pg=;
        fh=UuEQbJn9VXIQPHRIrT7E+w2OJFLjqDsX9s0/fabtKr4=;
        b=M/DZlNuGcR+cy0u3FKdZUzUq9B3gtliTNiOFiH5xXJX/5eO9An6ReRMByrbxbwRUR7
         xQMjeZwSKzTaqrGQ5ob4vGFMLzy4pl2P5AA5D9E03hoXqniTGq79lIumrkRQsdvKiABw
         1801MCSQvZ8AifDP2ciFympCw//TNKO6ruH9Y9kLkNtrZTy8+sow50wmvQFa9q5zMRlD
         I+g7xivz2H0KRg7BDSY/YSmvm7a05ti0zUNpLVxPk7y+6uTsEKFdye//Hg6bQqzgTi0J
         b3vSsgosJpC3s5nEgkDn9/0K6ZwKZwewc5DXaA3v/Jnjw4166uUZHXjQx7E+FzseQjyd
         UFxw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oO4La249;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1ea3767si4311941cf.7.2026.01.20.09.20.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 09:20:08 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id d75a77b69052e-5014b5d8551so1542991cf.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 09:20:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768929608; cv=none;
        d=google.com; s=arc-20240605;
        b=XNnY5h/oFGAa8nlfJo/IHC69mKKkNIu9A0RgAW0COby/N6f/0R4ACyaC8e5QWGJ2wX
         3puI5hixp5cV2IdQy/xZ8nI/fCs/PV/BnvgF7djnzqu6VCGn0MZqB4hFvpB6TObwcsXn
         Ho42VmV7K4Je8k4BbljpmNXe24VjbWOOSJuc8CBMSPLof4YJCEvCmhjBm1nOChryAuz1
         6EUd/uiRTK1Lk48w77p1lNHuCwaqSKyIsfYhhuKDX8c1ttNxjU0FS9Rpur8zE1bwfR6E
         LCqOBPKkENJFDt0W7xNLdK5cIyX4h76JAq7DTFfmypydbvMBczVCn9+jr3jeFV+gSyYd
         OX3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XjgInJxzHZA1FL2RVNq/kScJMYVHdTMpDmOcyNlB2Pg=;
        fh=UuEQbJn9VXIQPHRIrT7E+w2OJFLjqDsX9s0/fabtKr4=;
        b=A4P8ynDZNntDI6Xq3glnmRY2FnaT+3JCiRsPf9LYm5oHZEcMx3QBK02IhiyG54hY41
         L8OllM21DaZIkPhgg+jEuxWZ5QSwD37s9mcipsaqq4oUG7oVUltUCXcQeqMSj7d1BqtS
         zpCbi8BHlvLw7I9csdb4HjNi/Asworgxac/gUBh9vfcWT3agX+9CMniAoYq00qQXWrwD
         kyq+Jt8o4NcqiZDrWzwqQ69bOMFLH20pXTBorN1srYwKAm8W4040FdPWXkgPxbRHy8zo
         OTK1qA6oV/UG8ygn43RU6JjraGMEhFscEh9MPy2kBHa64asBpA9AUNoiXRlZoQJ9DQ9I
         Rstg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUGiIQVxqzC57ZXD60TpGZ5XeIP6PAOuZRLkyU8SIuiNP5tK4KsjqhGtUyxgirXvcJmn0Lrdnje+54=@googlegroups.com
X-Gm-Gg: AY/fxX4z13GoJ1oYaMPmu+WUmKQZiQUb+USnJ3xOmvnYTZci/2QpqJUjJexW+JL3NIY
	zauV2IJhOdtQEUqjfzLqornXZeOcg5/6IAjvubWpB/EJznR8u4FFWC2AkG2WjE728GWAcdMUbv4
	cduPMYmYVDYJ46eLK4JdwplRSUzo6S2TzlnNO2hhJEIto6bn8HtGq32Ewqm8gNG7mdpmiyTc01o
	ppSJfgMDo126MD59SiPExNfX+lAIkiIHj0Ec9rFIfMI/MfdqqWxIMS9xmybca5BP3anGyZ/G7Dg
	gyBep0eRYOMlcaW6pQ+TNVRPGaVBcFa/9Q==
X-Received: by 2002:ac8:7f49:0:b0:4ed:ff77:1a85 with SMTP id
 d75a77b69052e-502b07275d9mr30014031cf.17.1768929607523; Tue, 20 Jan 2026
 09:20:07 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 17:19:56 +0000
X-Gm-Features: AZwV_Qi9JsdZs4u4zpyMKVEbr1yatFKMUCA5FvcV_dcEEUthHo8JPVRpfNJYn0g
Message-ID: <CAJuCfpErRjMi2aCCThHiS1F_LvaXjkVQvX9kJjqrpw8YnXoNBA@mail.gmail.com>
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial list
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oO4La249;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBSXSX3FQMGQELKQ3LZY];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,suse.cz:email,mail-qk1-x738.google.com:rdns,mail-qk1-x738.google.com:helo]
X-Rspamd-Queue-Id: 0D7CB48743
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> At this point we have sheaves enabled for all caches, but their refill
> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> slabs - now a redundant caching layer that we are about to remove.
>
> The refill will thus be done from slabs on the node partial list.
> Introduce new functions that can do that in an optimized way as it's
> easier than modifying the __kmem_cache_alloc_bulk() call chain.
>
> Extend struct partial_context so it can return a list of slabs from the
> partial list with the sum of free objects in them within the requested
> min and max.
>
> Introduce get_partial_node_bulk() that removes the slabs from freelist
> and returns them in the list.
>
> Introduce get_freelist_nofreeze() which grabs the freelist without
> freezing the slab.
>
> Introduce alloc_from_new_slab() which can allocate multiple objects from
> a newly allocated slab where we don't need to synchronize with freeing.
> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> the cache is a non-debug one so it can avoid some actions.
>
> Introduce __refill_objects() that uses the functions above to fill an
> array of objects. It has to handle the possibility that the slabs will
> contain more objects that were requested, due to concurrent freeing of
> objects to those slabs. When no more slabs on partial lists are
> available, it will allocate new slabs. It is intended to be only used
> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
>
> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> only refilled from contexts that allow spinning, or even blocking.
>

Some nits, but otherwise LGTM.
Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 284 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++=
+-----
>  1 file changed, 264 insertions(+), 20 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 9bea8a65e510..dce80463f92c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -246,6 +246,9 @@ struct partial_context {
>         gfp_t flags;
>         unsigned int orig_size;
>         void *object;
> +       unsigned int min_objects;
> +       unsigned int max_objects;
> +       struct list_head slabs;
>  };
>
>  static inline bool kmem_cache_debug(struct kmem_cache *s)
> @@ -2650,9 +2653,9 @@ static void free_empty_sheaf(struct kmem_cache *s, =
struct slab_sheaf *sheaf)
>         stat(s, SHEAF_FREE);
>  }
>
> -static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> -                                  size_t size, void **p);
> -
> +static unsigned int
> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int=
 min,
> +                unsigned int max);
>
>  static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>                          gfp_t gfp)
> @@ -2663,8 +2666,8 @@ static int refill_sheaf(struct kmem_cache *s, struc=
t slab_sheaf *sheaf,
>         if (!to_fill)
>                 return 0;
>
> -       filled =3D __kmem_cache_alloc_bulk(s, gfp, to_fill,
> -                                        &sheaf->objects[sheaf->size]);
> +       filled =3D __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
> +                       to_fill, to_fill);
>
>         sheaf->size +=3D filled;
>
> @@ -3522,6 +3525,63 @@ static inline void put_cpu_partial(struct kmem_cac=
he *s, struct slab *slab,
>  #endif
>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
>
> +static bool get_partial_node_bulk(struct kmem_cache *s,
> +                                 struct kmem_cache_node *n,
> +                                 struct partial_context *pc)
> +{
> +       struct slab *slab, *slab2;
> +       unsigned int total_free =3D 0;
> +       unsigned long flags;
> +
> +       /* Racy check to avoid taking the lock unnecessarily. */
> +       if (!n || data_race(!n->nr_partial))
> +               return false;
> +
> +       INIT_LIST_HEAD(&pc->slabs);
> +
> +       spin_lock_irqsave(&n->list_lock, flags);
> +
> +       list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> +               struct freelist_counters flc;
> +               unsigned int slab_free;
> +
> +               if (!pfmemalloc_match(slab, pc->flags))
> +                       continue;
> +
> +               /*
> +                * determine the number of free objects in the slab racil=
y
> +                *
> +                * due to atomic updates done by a racing free we should =
not
> +                * read an inconsistent value here, but do a sanity check=
 anyway
> +                *
> +                * slab_free is a lower bound due to subsequent concurren=
t
> +                * freeing, the caller might get more objects than reques=
ted and
> +                * must deal with it
> +                */
> +               flc.counters =3D data_race(READ_ONCE(slab->counters));
> +               slab_free =3D flc.objects - flc.inuse;
> +
> +               if (unlikely(slab_free > oo_objects(s->oo)))
> +                       continue;
> +
> +               /* we have already min and this would get us over the max=
 */
> +               if (total_free >=3D pc->min_objects
> +                   && total_free + slab_free > pc->max_objects)
> +                       break;
> +
> +               remove_partial(n, slab);
> +
> +               list_add(&slab->slab_list, &pc->slabs);
> +
> +               total_free +=3D slab_free;
> +               if (total_free >=3D pc->max_objects)
> +                       break;

From the above code it seems like you are trying to get at least
pc->min_objects and as close as possible to the pc->max_objects
without exceeding it (with a possibility that we will exceed both
min_objects and max_objects in one step). Is that indeed the intent?
Because otherwise could could simplify these conditions to stop once
you crossed pc->min_objects.

> +       }
> +
> +       spin_unlock_irqrestore(&n->list_lock, flags);
> +       return total_free > 0;
> +}
> +
>  /*
>   * Try to allocate a partial slab from a specific node.
>   */
> @@ -4448,6 +4508,33 @@ static inline void *get_freelist(struct kmem_cache=
 *s, struct slab *slab)
>         return old.freelist;
>  }
>
> +/*
> + * Get the slab's freelist and do not freeze it.
> + *
> + * Assumes the slab is isolated from node partial list and not frozen.
> + *
> + * Assumes this is performed only for caches without debugging so we
> + * don't need to worry about adding the slab to the full list

nit: Missing a period sign at the end of the above sentence.

> + */
> +static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct s=
lab *slab)

I was going to comment on similarities between
get_freelist_nofreeze(), get_freelist() and freeze_slab() and
possibility of consolidating them but then I saw you removing the
other functions in the next patch. So, I'm mentioning it here merely
for other reviewers not to trip on this.

> +{
> +       struct freelist_counters old, new;
> +
> +       do {
> +               old.freelist =3D slab->freelist;
> +               old.counters =3D slab->counters;
> +
> +               new.freelist =3D NULL;
> +               new.counters =3D old.counters;
> +               VM_WARN_ON_ONCE(new.frozen);
> +
> +               new.inuse =3D old.objects;
> +
> +       } while (!slab_update_freelist(s, slab, &old, &new, "get_freelist=
_nofreeze"));
> +
> +       return old.freelist;
> +}
> +
>  /*
>   * Freeze the partial slab and return the pointer to the freelist.
>   */
> @@ -4471,6 +4558,65 @@ static inline void *freeze_slab(struct kmem_cache =
*s, struct slab *slab)
>         return old.freelist;
>  }
>
> +/*
> + * If the object has been wiped upon free, make sure it's fully initiali=
zed by
> + * zeroing out freelist pointer.
> + *
> + * Note that we also wipe custom freelist pointers.
> + */
> +static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
> +                                                  void *obj)
> +{
> +       if (unlikely(slab_want_init_on_free(s)) && obj &&
> +           !freeptr_outside_object(s))
> +               memset((void *)((char *)kasan_reset_tag(obj) + s->offset)=
,
> +                       0, sizeof(void *));
> +}
> +
> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct sla=
b *slab,
> +               void **p, unsigned int count, bool allow_spin)
> +{
> +       unsigned int allocated =3D 0;
> +       struct kmem_cache_node *n;
> +       unsigned long flags;
> +       void *object;
> +
> +       if (!allow_spin && (slab->objects - slab->inuse) > count) {
> +
> +               n =3D get_node(s, slab_nid(slab));
> +
> +               if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> +                       /* Unlucky, discard newly allocated slab */
> +                       defer_deactivate_slab(slab, NULL);
> +                       return 0;
> +               }
> +       }
> +
> +       object =3D slab->freelist;
> +       while (object && allocated < count) {
> +               p[allocated] =3D object;
> +               object =3D get_freepointer(s, object);
> +               maybe_wipe_obj_freeptr(s, p[allocated]);
> +
> +               slab->inuse++;
> +               allocated++;
> +       }
> +       slab->freelist =3D object;
> +
> +       if (slab->freelist) {

nit: It's a bit subtle that the checks for slab->freelist here and the
earlier one for ((slab->objects - slab->inuse) > count) are
effectively equivalent. That's because this is a new slab and objects
can't be freed into it concurrently. I would feel better if both
checks were explicitly the same, like having "bool extra_objs =3D
(slab->objects - slab->inuse) > count;" and use it for both checks.
But this is minor, so feel free to ignore.

> +
> +               if (allow_spin) {
> +                       n =3D get_node(s, slab_nid(slab));
> +                       spin_lock_irqsave(&n->list_lock, flags);
> +               }
> +               add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +               spin_unlock_irqrestore(&n->list_lock, flags);
> +       }
> +
> +       inc_slabs_node(s, slab_nid(slab), slab->objects);
> +       return allocated;
> +}
> +
>  /*
>   * Slow path. The lockless freelist is empty or we need to perform
>   * debugging duties.
> @@ -4913,21 +5059,6 @@ static __always_inline void *__slab_alloc_node(str=
uct kmem_cache *s,
>         return object;
>  }
>
> -/*
> - * If the object has been wiped upon free, make sure it's fully initiali=
zed by
> - * zeroing out freelist pointer.
> - *
> - * Note that we also wipe custom freelist pointers.
> - */
> -static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
> -                                                  void *obj)
> -{
> -       if (unlikely(slab_want_init_on_free(s)) && obj &&
> -           !freeptr_outside_object(s))
> -               memset((void *)((char *)kasan_reset_tag(obj) + s->offset)=
,
> -                       0, sizeof(void *));
> -}
> -
>  static __fastpath_inline
>  struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags=
)
>  {
> @@ -5388,6 +5519,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_c=
ache *s,
>         return ret;
>  }
>
> +static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> +                                  size_t size, void **p);
> +
>  /*
>   * returns a sheaf that has at least the requested size
>   * when prefilling is needed, do so with given gfp flags
> @@ -7463,6 +7597,116 @@ void kmem_cache_free_bulk(struct kmem_cache *s, s=
ize_t size, void **p)
>  }
>  EXPORT_SYMBOL(kmem_cache_free_bulk);
>
> +static unsigned int
> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int=
 min,
> +                unsigned int max)
> +{
> +       struct slab *slab, *slab2;
> +       struct partial_context pc;
> +       unsigned int refilled =3D 0;
> +       unsigned long flags;
> +       void *object;
> +       int node;
> +
> +       pc.flags =3D gfp;
> +       pc.min_objects =3D min;
> +       pc.max_objects =3D max;
> +
> +       node =3D numa_mem_id();
> +
> +       if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +               return 0;
> +
> +       /* TODO: consider also other nodes? */
> +       if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> +               goto new_slab;
> +
> +       list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +               list_del(&slab->slab_list);
> +
> +               object =3D get_freelist_nofreeze(s, slab);
> +
> +               while (object && refilled < max) {
> +                       p[refilled] =3D object;
> +                       object =3D get_freepointer(s, object);
> +                       maybe_wipe_obj_freeptr(s, p[refilled]);
> +
> +                       refilled++;
> +               }
> +
> +               /*
> +                * Freelist had more objects than we can accommodate, we =
need to
> +                * free them back. We can treat it like a detached freeli=
st, just
> +                * need to find the tail object.
> +                */
> +               if (unlikely(object)) {
> +                       void *head =3D object;
> +                       void *tail;
> +                       int cnt =3D 0;
> +
> +                       do {
> +                               tail =3D object;
> +                               cnt++;
> +                               object =3D get_freepointer(s, object);
> +                       } while (object);
> +                       do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
> +               }
> +
> +               if (refilled >=3D max)
> +                       break;
> +       }
> +
> +       if (unlikely(!list_empty(&pc.slabs))) {
> +               struct kmem_cache_node *n =3D get_node(s, node);
> +
> +               spin_lock_irqsave(&n->list_lock, flags);
> +
> +               list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_lis=
t) {
> +
> +                       if (unlikely(!slab->inuse && n->nr_partial >=3D s=
->min_partial))
> +                               continue;
> +
> +                       list_del(&slab->slab_list);
> +                       add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +               }
> +
> +               spin_unlock_irqrestore(&n->list_lock, flags);
> +
> +               /* any slabs left are completely free and for discard */
> +               list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_lis=
t) {
> +
> +                       list_del(&slab->slab_list);
> +                       discard_slab(s, slab);
> +               }
> +       }
> +
> +
> +       if (likely(refilled >=3D min))
> +               goto out;
> +
> +new_slab:
> +
> +       slab =3D new_slab(s, pc.flags, node);
> +       if (!slab)
> +               goto out;
> +
> +       stat(s, ALLOC_SLAB);
> +
> +       /*
> +        * TODO: possible optimization - if we know we will consume the w=
hole
> +        * slab we might skip creating the freelist?
> +        */
> +       refilled +=3D alloc_from_new_slab(s, slab, p + refilled, max - re=
filled,
> +                                       /* allow_spin =3D */ true);
> +
> +       if (refilled < min)
> +               goto new_slab;

Ok, allow_spin=3Dtrue saves us from a potential infinite loop here. LGTM.

> +out:
> +
> +       return refilled;
> +}
> +
>  static inline
>  int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t si=
ze,
>                             void **p)
>
> --
> 2.52.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpErRjMi2aCCThHiS1F_LvaXjkVQvX9kJjqrpw8YnXoNBA%40mail.gmail.com.
