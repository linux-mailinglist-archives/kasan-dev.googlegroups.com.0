Return-Path: <kasan-dev+bncBC7OD3FKWUERBSPMYXFQMGQEDCCJDVI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UOSKMUt2cWngHgAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBSPMYXFQMGQEDCCJDVI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 01:58:51 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 53D786021F
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 01:58:51 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-78fac0d55f1sf6681597b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 16:58:51 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769043530; cv=pass;
        d=google.com; s=arc-20240605;
        b=bfn5FD2uXs9cA1cZf2p+SYk9je8rweTOhtIgKlOwJZBfGhVKPS9AKG4yXkPRWATPwn
         Qj1fO4qWvQrshm3sOEjfgeKwo6h1L09cgCtWLTq1fvuwSzWWNWt/Uify+8YHUWvoqzJB
         TqFI6a3LMon+6VMN6SoS0v+QVhPfs1eisKrQda/5BlscLbaAvsFnoH6Bby/MpeKboncK
         zx8Ez0AFe92Muw0fahMWw3UqQgbm0Xj43pGSnD6RLCPw+JG1CwItmeyXnhWHiisukr8Z
         OHs7pVTNUbzYzYRbehVBkyNyRG+7+UuSVgNBcb7/kxPUkgzUmTV9K09gCK4c7xR2dmjJ
         DbfQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oEjTcr5JfXSReYRcVv8hihARhDwDbVQaFY7M7kbws4k=;
        fh=euLvuU61YOuKBrcW2AsHwuiWyPqXWQWWUhw5FhrvvuQ=;
        b=gIEFIJ/zAyYzVO0Ee4v1x9YI9IuI8GmvztS05d2ny1FYuFHEB9o5sQ6BHoIIRnooEb
         aq6OmBWeG+W1x28rV+BQKd8i3MycRUsOsMHs10nB9XdtrsxU6HfiPZcjsMFmfWjaERVR
         lvpvvMirXtsvpq3Vc/i+0ji29x0j8HZ26eOQInguQZZKMnBHrp6F9fEKKQgyRdGIyEc3
         rfiwYpqmf15WNYKL8uOO3pyOSY4TpsP9UfWxU/17cVOVlckqWiKIlNtNHD3RQxNRooSq
         pwPOrO2xsJNS2A4R2UfodaFha2PDMVv89BAICNnZGw2kBsoLf0f+cSZyJ5rLMWMduFgS
         gdsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Etn+cVnm;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769043530; x=1769648330; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oEjTcr5JfXSReYRcVv8hihARhDwDbVQaFY7M7kbws4k=;
        b=P+L21VFNq5r4LMm43fPFKjB5KZpQjJRJFrKaRu+0gj/MVAKDKd3zfj/vEy2OC17nsl
         a6OK9cHutlGKEAVAmPnsiYPhFccr+Y2JlZwhKTbpLc+Dwz7MtchM6I7u4PfoXoV00f0i
         CmCj8H1juwhpqnHGUT4vIbxMfpey1GkStyWQe1eqt5O0ILdGuggfSSz5CqEH0PCKpC8l
         UfF/IWDUNMm4No3pZg67X9XvkwWObOL8fy+gzX4eVMrOSoDJkTMcNmkMb1hvDTFklpg6
         iVQuXLXcb4l5xyZrsXLwnwgO2Jfits/IzSXpYrkJEFtINZDFrYFRGc6msQwq4nLRooIp
         uqSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769043530; x=1769648330;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=oEjTcr5JfXSReYRcVv8hihARhDwDbVQaFY7M7kbws4k=;
        b=q0Itn8GXU3AahBWJXZfd0uPriJQr5ZZtRyxl+JOPkMxiAJ+2Pl4yIRYRIuuZ6oy82G
         tqydnuHPqKLrOwcBXa6rYHit2yW7R7btqyajSAxqbO9BWOJsRgrHNyLVDfZHSOMLBT2T
         6xv+T7REXHPoIDTZSPDSaaMn793b36uZjNq6xSq4XVikufX+DtnfP8inf9Y52ALkrX6s
         fK8E7EMy6YgyO3xR+h47TJlYFf39x7Sk3WDBwpjV9lzFabGuAFsnDn1YPFv2HuGQ+UVW
         7IicAac6I1Wgn9fljJYFc1ARzoryQpDosWgkdjF+FrEAScdOf3X7SJH2HKxBDH2uiy/5
         cOEA==
X-Forwarded-Encrypted: i=3; AJvYcCXWrlYNjwJLTKg5VIbGgSBBtuc2n0N4O1MTmwpOsu9w0aI+LUjsl3l0C6zXfA192vFCASOsfA==@lfdr.de
X-Gm-Message-State: AOJu0Yz+ex2Bznesdn7mv/RJgkd6VenrprRKDTr1VFz9a0sHBfOAIATS
	63Gj2qWF48CesgDoL/DKPpq6A4foRQHq2YI6WiIfQQ7oX5XKqWpBrf5n
X-Received: by 2002:a53:c40e:0:b0:646:7a2e:5963 with SMTP id 956f58d0204a3-64916520506mr11498296d50.92.1769043529819;
        Wed, 21 Jan 2026 16:58:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Heh08Pa1KCpTOSqLq6irRVSyvniIx8WFiFAO/LIfDrnQ=="
Received: by 2002:a53:b005:0:b0:607:623b:bb59 with SMTP id 956f58d0204a3-649516a33f4ls299388d50.2.-pod-prod-02-us;
 Wed, 21 Jan 2026 16:58:48 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWCsaddnK30EOs7RTjZKtIkq3FggA2keskWUrWZEC1T86FvS3Ldl4ml8QxP+9tHEzOpTcfjkx8aheg=@googlegroups.com
X-Received: by 2002:a05:690e:1344:b0:646:7ae4:11e9 with SMTP id 956f58d0204a3-6491648afe7mr16532755d50.15.1769043528790;
        Wed, 21 Jan 2026 16:58:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769043528; cv=pass;
        d=google.com; s=arc-20240605;
        b=JVtyWiQyB/yKoJuCvMl8sqH0qCi5qsWjsRMMfuGx6+0Hlo2UMQ77FpfOI2D83Gsq+o
         MJpFuK50HtDnnOrPZ1M2BZmeOMRN3sHGIzUPkmPmEUSR48n3S37uhihz0i0HWwWfLIDC
         g+ZCg05JnTcDcv2nG7lBLvlxhChz3J0FvxJHfEQAfR+Y8TA3P0dqAurMoFiOeV3BbjPP
         cfc0VdJqJ+nmW/P1NiMQMVZg7L/Tu4yFI34b918UgBGa2y6BHTdqP245wOrmsfAham67
         JHUPVpqyy5Tf1wQ+z+J9J+F/nnklwTUsSDYvo5Gw641iXYFZbJYjO+3k7GEalvzMZGjZ
         6p2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VLIh79S7FhXMOMoT5i8cYC6nflwvZaP3UE034p5mOJs=;
        fh=o3W8ZS1DUvf/hKuvgY1WWVWEsiIXHHdL7Pn6WjJNfgs=;
        b=MMGU1bEwyXDFFT5Hpa+QvD7KyfWQjCOz9EVAcUVowGc21fKPqr/r0pa+cwYl0n/8Xe
         Q5WJwogmbRQHYlNB9hdIoyVXv8i39xxjkf4qrp4Hw2R1Aw5qXWD8iU5Z8zrVXouEjDA/
         9/47ahaLzUNJwGd/olcTGrTqgP8n7KLXr98ctU2VRMGXgJbI7dcOajWnC2Yl/gYUdec1
         f/qPK7duhzE48peqyLJG/KQh+KvSqhqbuU1TAl0yQy9GZovEpfigd2RxZ5RbQ3oaVeHR
         KnF2uZZ+MfenAN2ALqlsNJ3T6v70Rr6ujw4NBKQ7f7QnUyFNLT//WE7JFxxivX867GHs
         NBsg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Etn+cVnm;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-649170a0c2csi523654d50.5.2026.01.21.16.58.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 16:58:48 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id d75a77b69052e-50299648ae9so73301cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 16:58:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769043528; cv=none;
        d=google.com; s=arc-20240605;
        b=MrTrjv0+5lFDaAnm8pvTFeA3xpEqrJtlxRQ5sP7qXDgWCP29BKDveGJxbghLPYlSov
         0LFaIcFnWEYoFBKGe582QBDqGHNw92D10aldx36e7tUDQrdinfB0CRugpbL/O9Z5R6e4
         flEAzVwC4CdqhRtTApUH3iQzg5XL+lKWFYoYBSnxSljnclAIZaQOHoxOH+o7MOWgPtsn
         paMF2slJe/uixp06YLr8Zi9RV3cLIHcA1JrBJmpuQmWgPRE9XhrGmLU7CZge7SkYsZ0f
         doLPv2FRvQ7z2sKeJAMXrOLtRz0UvbybDU8GBY0zfkxfh1c933oH75MW/ScdCsrbqMN2
         gQXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VLIh79S7FhXMOMoT5i8cYC6nflwvZaP3UE034p5mOJs=;
        fh=o3W8ZS1DUvf/hKuvgY1WWVWEsiIXHHdL7Pn6WjJNfgs=;
        b=VswfuA8Ta5nPafKBevp4UMqW+nZv5Ym2GbmBo+ORJj1NdI9T+9EtgbNmdCwCfjhC5S
         RNFbSNqgpThyuOw0hh/5NZZ10rAuC4+qfVwPoGEdpan2SF+8QzQr+JXSvh+0bI9nLSA6
         mzzNGo2H8p/cMGg+SJAM2oPbBBUjnM/O/EPR4452MFrR/nsmjGzjhj0EhnT6wB4zsUap
         +QO13F/uo2s6WcTyPOeH2HUpSy1Alg6LAbsxUaD0Oe26xIa7cK/u97KHghA8uewEj363
         IoyBNthBH94fxoKdiHlBzZCrQVxaUfc73yNjoSwYy6b8Q9mm+ONOzHOjTOivJjGp1PnD
         ojAw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWvF/IBOam6Y8der7TIecbCbVkEIeQ1y5OQWUPpIwlxN0R1d93S9cxizN8sartHPkrNDTrpfEf9M/c=@googlegroups.com
X-Gm-Gg: AZuq6aKPd38TPeBIBkaaQl98xAyp5SVrKoS1Yq8afTNayKuvDfS+cKVvmeSZYpxNYeW
	jyhmgdev1j//+cjMZB11Y7fO6YJl27PmSWnNcWCNl+Jb5BN9dcZGUI7Ze9E+8JEd10e+8yiPXyz
	7IyMvcgR9HmgZMKmbNeYh/0+aivNRqUmsQqW63MgTD3G5j2lk/1tjYg5Wphlm3T385/RELloOlP
	ELeKJGNA1CL0VX7bCMxb2lotr8Qy36FrqsKG+my6ASLEB6YzQppBmjCs1BAeQMza4JKCgM5HnHr
	xRmi2HZJ4mynZPUuhbOWRoU=
X-Received: by 2002:a05:622a:15cb:b0:4ed:ff77:1a85 with SMTP id
 d75a77b69052e-502ece4dbc5mr3059331cf.17.1769043527916; Wed, 21 Jan 2026
 16:58:47 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-20-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-20-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Jan 2026 00:58:36 +0000
X-Gm-Features: AZwV_Qgalo5BT2cF8nB5P98paznJER_XoJhiYL5n6D0vsto2yVGgbP9TwAgaUBk
Message-ID: <CAJuCfpF8xYb2j57HzO_-cfaTrOd-+jyv8pr4uFV1KwaSxKvghg@mail.gmail.com>
Subject: Re: [PATCH v3 20/21] mm/slub: remove DEACTIVATE_TO_* stat items
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
 header.i=@google.com header.s=20230601 header.b=Etn+cVnm;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBSPMYXFQMGQEDCCJDVI];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,mail-yw1-x113c.google.com:helo,mail-yw1-x113c.google.com:rdns]
X-Rspamd-Queue-Id: 53D786021F
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 2:41=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> The cpu slabs and their deactivations were removed, so remove the unused
> stat items. Weirdly enough the values were also used to control
> __add_partial() adding to head or tail of the list, so replace that with
> a new enum add_mode, which is cleaner.
>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Same question about UAPI breakage, but otherwise LGTM.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  mm/slub.c | 31 +++++++++++++++----------------
>  1 file changed, 15 insertions(+), 16 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 7ec7049c0ca5..c12e90cb2fca 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -324,6 +324,11 @@ static void debugfs_slab_add(struct kmem_cache *);
>  static inline void debugfs_slab_add(struct kmem_cache *s) { }
>  #endif
>
> +enum add_mode {
> +       ADD_TO_HEAD,
> +       ADD_TO_TAIL,
> +};
> +
>  enum stat_item {
>         ALLOC_PCS,              /* Allocation from percpu sheaf */
>         ALLOC_FASTPATH,         /* Allocation from cpu slab */
> @@ -343,8 +348,6 @@ enum stat_item {
>         CPUSLAB_FLUSH,          /* Abandoning of the cpu slab */
>         DEACTIVATE_FULL,        /* Cpu slab was full when deactivated */
>         DEACTIVATE_EMPTY,       /* Cpu slab was empty when deactivated */
> -       DEACTIVATE_TO_HEAD,     /* Cpu slab was moved to the head of part=
ials */
> -       DEACTIVATE_TO_TAIL,     /* Cpu slab was moved to the tail of part=
ials */
>         DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects =
*/
>         DEACTIVATE_BYPASS,      /* Implicit deactivation */
>         ORDER_FALLBACK,         /* Number of times fallback was necessary=
 */
> @@ -3268,10 +3271,10 @@ static inline void slab_clear_node_partial(struct=
 slab *slab)
>   * Management of partially allocated slabs.
>   */
>  static inline void
> -__add_partial(struct kmem_cache_node *n, struct slab *slab, int tail)
> +__add_partial(struct kmem_cache_node *n, struct slab *slab, enum add_mod=
e mode)
>  {
>         n->nr_partial++;
> -       if (tail =3D=3D DEACTIVATE_TO_TAIL)
> +       if (mode =3D=3D ADD_TO_TAIL)
>                 list_add_tail(&slab->slab_list, &n->partial);
>         else
>                 list_add(&slab->slab_list, &n->partial);
> @@ -3279,10 +3282,10 @@ __add_partial(struct kmem_cache_node *n, struct s=
lab *slab, int tail)
>  }
>
>  static inline void add_partial(struct kmem_cache_node *n,
> -                               struct slab *slab, int tail)
> +                               struct slab *slab, enum add_mode mode)
>  {
>         lockdep_assert_held(&n->list_lock);
> -       __add_partial(n, slab, tail);
> +       __add_partial(n, slab, mode);
>  }
>
>  static inline void remove_partial(struct kmem_cache_node *n,
> @@ -3375,7 +3378,7 @@ static void *alloc_single_from_new_slab(struct kmem=
_cache *s, struct slab *slab,
>         if (slab->inuse =3D=3D slab->objects)
>                 add_full(s, n, slab);
>         else
> -               add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +               add_partial(n, slab, ADD_TO_HEAD);
>
>         inc_slabs_node(s, nid, slab->objects);
>         spin_unlock_irqrestore(&n->list_lock, flags);
> @@ -3996,7 +3999,7 @@ static unsigned int alloc_from_new_slab(struct kmem=
_cache *s, struct slab *slab,
>                         n =3D get_node(s, slab_nid(slab));
>                         spin_lock_irqsave(&n->list_lock, flags);
>                 }
> -               add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +               add_partial(n, slab, ADD_TO_HEAD);
>                 spin_unlock_irqrestore(&n->list_lock, flags);
>         }
>
> @@ -5064,7 +5067,7 @@ static noinline void free_to_partial_list(
>                         /* was on full list */
>                         remove_full(s, n, slab);
>                         if (!slab_free) {
> -                               add_partial(n, slab, DEACTIVATE_TO_TAIL);
> +                               add_partial(n, slab, ADD_TO_TAIL);
>                                 stat(s, FREE_ADD_PARTIAL);
>                         }
>                 } else if (slab_free) {
> @@ -5184,7 +5187,7 @@ static void __slab_free(struct kmem_cache *s, struc=
t slab *slab,
>          * then add it.
>          */
>         if (unlikely(was_full)) {
> -               add_partial(n, slab, DEACTIVATE_TO_TAIL);
> +               add_partial(n, slab, ADD_TO_TAIL);
>                 stat(s, FREE_ADD_PARTIAL);
>         }
>         spin_unlock_irqrestore(&n->list_lock, flags);
> @@ -6564,7 +6567,7 @@ __refill_objects_node(struct kmem_cache *s, void **=
p, gfp_t gfp, unsigned int mi
>                                 continue;
>
>                         list_del(&slab->slab_list);
> -                       add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +                       add_partial(n, slab, ADD_TO_HEAD);
>                 }
>
>                 spin_unlock_irqrestore(&n->list_lock, flags);
> @@ -7031,7 +7034,7 @@ static void early_kmem_cache_node_alloc(int node)
>          * No locks need to be taken here as it has just been
>          * initialized and there is no concurrent access.
>          */
> -       __add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +       __add_partial(n, slab, ADD_TO_HEAD);
>  }
>
>  static void free_kmem_cache_nodes(struct kmem_cache *s)
> @@ -8719,8 +8722,6 @@ STAT_ATTR(FREE_SLAB, free_slab);
>  STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
>  STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
>  STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
> -STAT_ATTR(DEACTIVATE_TO_HEAD, deactivate_to_head);
> -STAT_ATTR(DEACTIVATE_TO_TAIL, deactivate_to_tail);
>  STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
>  STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
>  STAT_ATTR(ORDER_FALLBACK, order_fallback);
> @@ -8823,8 +8824,6 @@ static struct attribute *slab_attrs[] =3D {
>         &cpuslab_flush_attr.attr,
>         &deactivate_full_attr.attr,
>         &deactivate_empty_attr.attr,
> -       &deactivate_to_head_attr.attr,
> -       &deactivate_to_tail_attr.attr,
>         &deactivate_remote_frees_attr.attr,
>         &deactivate_bypass_attr.attr,
>         &order_fallback_attr.attr,
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
AJuCfpF8xYb2j57HzO_-cfaTrOd-%2Bjyv8pr4uFV1KwaSxKvghg%40mail.gmail.com.
