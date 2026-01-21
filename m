Return-Path: <kasan-dev+bncBC7OD3FKWUERBKX2YPFQMGQEHAKFUNA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oBHQAC39cGmgbAAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBKX2YPFQMGQEHAKFUNA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:22:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 747C059D1D
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:22:04 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-29f2381ea85sf171635ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 08:22:04 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769012523; cv=pass;
        d=google.com; s=arc-20240605;
        b=GaBThDZQo2G8No6KAps8p58O+bRzIgV1cU8PUT1a6v1JeoXT+rk6FCEiK+DflevTGe
         kisfOQt+iA+xT9GfwfKbuIxUoNtxbhIcmLl2T+AQDjFaCflwpPR62PDM3Ivo/WlzuUZ5
         veIyW+XadKUwshewKuRhJdBvwckfeAl1rIUBPvo2rQLN05vDay/Ae5rJMZgAVoHmOJRT
         +t4NjkXWuufUd+Nl81Ha0l+CbarlKCvarEFPPlnfoSN5uHeAjrmeAOX+KdY1Qv2p+iFg
         3+olC37DOanbi2GJbWcvEUlN5n9y0MVnFNrCaRKJgfovxjHyfRi5VPK8aAKt64s/xPEk
         RPOw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CDpWZeBEzP1Jo8S+O5LS00AIELo/eKMSYGX2h//K9jc=;
        fh=+egNlPyteO+JapiDUAjSeumevvhsUgkzLvl73dWvqJ8=;
        b=ivfjciW2vHfZzTx9xOzbb2SiN6QQkeE50dTTLm8K9If0/yf4wu0r+XN4eqsz0oXwR5
         b+2m7UCuqBQwULMri5Jrcd4O3mGMjzqyHZ4CCXmcPqDzEh1Y7Tk/z0Yfom3jCoN1mhpG
         zHRqMmLN7wbUfUS7MvTCMq5COo5KDTsASIJKnLNjH/XBtEYpW7MD1SUOK84wQ6vTf6ou
         A/yCTMbC55Q8AscEhaiZg9jYsk4nzeJ4HyzzabVeKRKw4f1x3LBscq4qDpER7PhBvjBj
         D8pvgNZfyPPlZhf6R/hI/G0DK5+qrop8ngJkU8wIN+j1J1E1dxKeXH1nrmvPtWgG/6Zt
         L1DQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=au0UylQ2;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769012523; x=1769617323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CDpWZeBEzP1Jo8S+O5LS00AIELo/eKMSYGX2h//K9jc=;
        b=TujhKTdxscY9XLivGtHT0ooHt/flj+IuXrAPfCuHL92aLKl8iKMM+2jAbxF6wr19cX
         nbHbrAxrjbLAIXWv09dqsC26OlUfVECwGysOEhCT2oH2IsxopHba0B+YoCL1/QZFPPJh
         QlT0Qm0QBetiXvX2E805/p3gTNLY9pkEtzOYt2gdDF4Sd5mMrkWJxM3rwXGQ8I9rqyAG
         +B+H3iE1CYV+9clALMISflmDJ0na7K9lg67VmzlevJO+UMX/YObFiiG+yWnKGdjlybWX
         DIpIpWWxVC9J/6mwzT4Zwilkh50U3uGQW45YhUKKbCRxP58uKeg6a2HfACYfR3Krqgzc
         4+Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769012523; x=1769617323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=CDpWZeBEzP1Jo8S+O5LS00AIELo/eKMSYGX2h//K9jc=;
        b=GS8owNc76d54d1auIV30fcYK1PruxA9OfrBYA8OXkMc10WiF/K8uu0WtmC0au6V0bJ
         3hnoEPC5vJR9hvaDcU4PX3h5ssHKYgnt+5PmGqiovuLV4zRh3RvNM8dB+9jz/girzoft
         egv++BARG6mepg5A7fg83PAm/33au/VmasjOfMXL6Lmi51Ou0ruK3DsqyXNIwQykrrUH
         DNwOX7y2smQzy6WhLRgHLlfUrg3g2pgXYDAYRlw2ZNK/ZYUQeVL8jmAojrgwkRmcQRU/
         3gJBl4W7/wMy+LPJOVCrcAYzgTDjPW2ENr+UGtk+sCbAQxEvgFs9GZRTHG4EiA4Rqhqw
         KITw==
X-Forwarded-Encrypted: i=3; AJvYcCXneU6Qkx8DnWnpPAsMo9t91b/qE8HLbXttQl8gfudTE3GYtiOCznoFh4KGSPtCiXg3Z1mupw==@lfdr.de
X-Gm-Message-State: AOJu0Yxhyvx3naeNJRx7LTq2vz1M1Sx2dalFFMZElkBb+ysKn6eg1t//
	pIQcGdvbRIk5XdAn5/s8qVlCq8y5l9aDfJs4/fz2Qxn1M2Jb6UNeaf5k
X-Received: by 2002:a17:902:cf01:b0:2a7:9592:210a with SMTP id d9443c01a7336-2a795922506mr31527185ad.33.1769012522690;
        Wed, 21 Jan 2026 08:22:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hbc+po2ES7RbKGLXx2veUsoWWqTzJjzk+UR7lueevvJQ=="
Received: by 2002:a17:903:9c5:b0:268:589:fe0b with SMTP id d9443c01a7336-2a70312513dls41617595ad.0.-pod-prod-06-us;
 Wed, 21 Jan 2026 08:22:01 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUffcOxxH0RoNhYvdVtGRN8HT8vCOkaQb0SyFV3q5GqL3IgG/Xq4fB9YJjXbC5lFpiRG+pif5U7aGc=@googlegroups.com
X-Received: by 2002:a17:902:dac2:b0:2a7:8486:fe63 with SMTP id d9443c01a7336-2a78486fee3mr35426515ad.51.1769012521140;
        Wed, 21 Jan 2026 08:22:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769012521; cv=pass;
        d=google.com; s=arc-20240605;
        b=eWxC81BPZqEJupLamJsaoQmMhzil+mZ/MkbNqx5pVTbZjJlE4Pnns+ek1dg7IYVPG1
         +5wcnk3qvMpvx2RU7U2od7NRlbsUBk7WFtWWesBPxmuditS8eEfePTi0ggAg6eXIkykj
         dSJygztck9y0nCJGM8wQ2ybJkgKuB43PdagDuFGkq84P3bb1UNdKd3QQkBxQvkD+oq2t
         0Hxu+6P05/eSsS57Xx8hUcGNWcF+NhGZriGcl/zUavviPlK6C7zen52lgw2q1M5SPRd3
         dA9wFWKjRtx50xkoThGWv8O8F5NxKNi+5B+cqhPU/+46JgMWSOt2Dwy2mdHm9yxbamwA
         RGwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VdVLEMD28EfX+5P0zrv2LIUEohcfDySK6bn0IJ0lRR4=;
        fh=BZHHt2nplEOMry7jWtgPcfBIoixIZmHhArTNx5RSpDA=;
        b=losx09Drztt3wqUSZYhJP1mchlQiwHbOYIOvfTJUxipHNB9M/SzvXR4GtHZ3WhiT2I
         9X/7+90jBnR/P3l3jJKIIXhlCTj75yg9IItLL930aOMUi3SmEg7eFX/8RBtbJCaSPDO/
         a50b+B9/lZKoCTD/YJRFTLw+iayZb58jfM+mMhjgRlggHrOJsypJ8naOCCc7E8HOFlAi
         6FVCmGIr66vqtriozRfJ0lEEagLRIrq1jGc2JJTWmhmaLIGJO6yBtuYZF1E35WSQ0/Zg
         ceag81oUAjpPUzZKknVtC+s4P50mY+5+w5olhdny09B0rJzaPicB8cuyq5CpnO/8L3kW
         rw3w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=au0UylQ2;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a7bbe0f326si400885ad.8.2026.01.21.08.22.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 08:22:01 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-5014acad6f2so92741cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 08:22:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769012520; cv=none;
        d=google.com; s=arc-20240605;
        b=QCyeS0uMjhSN9+1INdQhLkt6kGCbVcHpGt5gfrrvQqZtiMv3dMTsnCdGg8wlsyKIVh
         5cKfwcQPuAlSz2aib3i0dpwE+TGXfotrN/X5APfPR3Rt0wYwjzOnFjFgtN+nDiYlqJzZ
         8ld2fNAgPIoNw2oxahpOU8z3fnbEu79XaU+FnWhQ4A6OIRqvghzmlkEKyKeVYRZSTac+
         x5kPA9f9TQx9c4Iql94nAWRGpw0NuwWKYGn4k/3wWVXCXp15Px6va9NwyWtzo3SxE2I4
         srW9J/d6GNBehtB80wMpxu5pzaTr7e/K3E0Tt5bN9Xk31FW4bKd9TxRfkhUYleTJUIT3
         JYAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VdVLEMD28EfX+5P0zrv2LIUEohcfDySK6bn0IJ0lRR4=;
        fh=BZHHt2nplEOMry7jWtgPcfBIoixIZmHhArTNx5RSpDA=;
        b=ezofNdP+dRzwJFPA6JQvs3OBFBlBqLjTV7o1vzpuc6ROhPMUCyOzkDhIyukEtFm3L6
         SUqRYbVOPvNJnKSNrf2RtJdlQEwROoOpfGe2U4EuAb4+rMN09dGT/V8cJ7JilE5a1KqE
         JlZEXF3+c4xSGEIcZZ5LPoqWvNAKPN6pnEvXosEwIahJqXT57AQgKqcjtleOvQIavnnu
         6pH74pQMx90BMj65if/PPUzQcUy/mkziYnR3MBBeCzzyQ9gfJfJPXQDMK2cPiK+3zG2e
         JjM66LWbxcQDFbYYqZtl23GVU+RSBwYZuvKHksd/5muyA94kakjS1LiAAPBJnkeOmSGG
         qwNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUVGO8ZC1sW2z19zIId4fUUP8mZBBIiSGcXoihqFuI+ozVRjgeEUj4YfEuZcqyQm5ynGtn1CHUb6yc=@googlegroups.com
X-Gm-Gg: AZuq6aLoPI4SgN4TZE8UIgCidAi08hcuykXcYbIbXzioXL6kgVJIMCNfVzvE83Hpn+M
	ERyZFzmEeJ93dXPPjpCzGq09E7xQjAus6M/GMjw3fl5TxXmD23SfWu+BK/nj5dlZqAxgj7Z1DYA
	jd8OMzzuQGsQNPAQhSeDannKOfKubqLddmcuC1G/RCjIk7YrMDYmY5AShzoGh3jEoyvihYA+QFi
	9aPCOSfNdyD7Mv+7v6jCnpFl5d8nRQOVV4zWxNdmO7UXpKuTJHMT1E4oh7pMNAwEZpw1JVthNuy
	f8BabNu4X/NvuNUu46NJpl0emVFO6IUDTw==
X-Received: by 2002:a05:622a:1998:b0:4e5:8707:d31 with SMTP id
 d75a77b69052e-502e1a7f7b3mr11247441cf.7.1769012519794; Wed, 21 Jan 2026
 08:21:59 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz> <CAJuCfpHaSg2O0vZhfAD+61i7Vq=T3OeQ=NXirXMd-2GCKRAgjg@mail.gmail.com>
 <aXAkwLsGP9rqamKL@hyeyoo>
In-Reply-To: <aXAkwLsGP9rqamKL@hyeyoo>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 16:21:47 +0000
X-Gm-Features: AZwV_QhmIp5S8mEMP1h6Gx-TWCdfCxovy5QQV_d0u6153x3grZV0j2owhClsj2k
Message-ID: <CAJuCfpFiLnvXF-yOVmLDNqQ9ZoJC1uKz3J7UNawhp5Epev=eNQ@mail.gmail.com>
Subject: Re: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=au0UylQ2;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
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
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBKX2YPFQMGQEHAKFUNA];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[suse.cz,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim,oracle.com:email]
X-Rspamd-Queue-Id: 747C059D1D
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 12:59=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> w=
rote:
>
> On Tue, Jan 20, 2026 at 10:25:27PM +0000, Suren Baghdasaryan wrote:
> > On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> > > @@ -5744,10 +5553,9 @@ static void __slab_free(struct kmem_cache *s, =
struct slab *slab,
> > >
> > >         /*
> > >          * Objects left in the slab. If it was not on the partial lis=
t before
> > > -        * then add it. This can only happen when cache has no per cp=
u partial
> > > -        * list otherwise we would have put it there.
> > > +        * then add it.
> > >          */
> > > -       if (!IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && unlikely(was_full=
)) {
> > > +       if (unlikely(was_full)) {
> >
> > This is not really related to your change but I wonder why we check
> > for was_full to detect that the slab was not on partial list instead
> > of checking !on_node_partial... They might be equivalent at this point
> > but it's still a bit confusing.
>
> If we only know that a slab is not on the partial list, we cannot
> manipulate its list because it may be on a linked list that cannot
> handle list manipulation outside function
> (e.g., pc.slabs in __refill_objects()).
>
> If it's not on the partial list, we can safely manipulate the list
> only when we know it was full. It's safe because full slabs are not
> supposed to be on any list (except for debug caches, where frees are
> done via free_to_partial_list()).

Ack. I guess I'm reading the above comment too literally. Thanks!

>
> --
> Cheers,
> Harry / Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpFiLnvXF-yOVmLDNqQ9ZoJC1uKz3J7UNawhp5Epev%3DeNQ%40mail.gmail.com.
