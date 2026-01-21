Return-Path: <kasan-dev+bncBC7OD3FKWUERBKVHYTFQMGQE2UYUGVQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0IXpKa0TcWkwdQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBKVHYTFQMGQE2UYUGVQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:58:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 40E175ADF3
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:58:05 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2a0bae9acd4sf530005ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 09:58:05 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769018283; cv=pass;
        d=google.com; s=arc-20240605;
        b=EhaVYBvryyB2MclFdHJkvs3JdbWWy7gD+4XRBG2FOaIj3TMsbyEljy1TGBtGDrkscO
         /aP0vm1zEzfdJ+KAoIEReF0mo+vNeZOaxAYo+oepyrdBBhYDmDo81/c+0m8s4AcRTJGz
         KQbHsKoB5tYpbfRoMY3LVcMiK22U1Wfn5Xg0c0SwSebW1lQGtPMxe5HGYHG7CxS8rxdY
         ktVLxf2iRekU5KX3HMYIbFH+FYqQ5nSJ17SHxUo1aO+R4E0B/bbkZllndENo6juWMSMT
         VQZkJAOwQKYFKvVplkf3nt+F9K3Glu9epSBjCYuBh9nPRaixfnuxeCjNFfNAoIzDadaW
         qvIA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9dWm5k5tm5kK9MeyjS+3N67tX+D0ZnKQ2qzzD7uPURw=;
        fh=7/EIbl2ijBhz7hVNoGFl3Hy0tf9R1I+tvzMaiufB/6k=;
        b=GMlEbBBanagV2mADhNB9Pb5Daw4LYzR5EjtJs39OPY5QFxIeEFKKHNsjS0ldbWxJOz
         dPVtqqwlNtnvoZC6AattQaL4jS0fVbcIDI629za1lnkPmgwgzytHc0KvcmtV6bdl12yB
         gsqkvc6ym9/2hOPQcA/7SwBdzpizsaAk3Z1sCSASJT8KKihoBjQx8KAXys4SdvZtZ/dW
         qYIJu2l3kgnFsR/sWd/4smfiLB67DCxedY7jw8cv0UDqHO4tvrBGL80O35KP3Eo2AM6L
         w8ICssDG1pqpHTsRRHx0el4guAXRvyqVWyHO9v/sgtii7Hl8I0JzTc+EqRcuNeXM2OUR
         qF3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P7Zlabya;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769018283; x=1769623083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9dWm5k5tm5kK9MeyjS+3N67tX+D0ZnKQ2qzzD7uPURw=;
        b=R6i6RpsjBQobV4QyHGfk5iR7kwylLS/lmpZE9x4j/AhMXkgYNW5IaBZKZy9ufVvK7Z
         RJQqeuNYMMEprdRJdalbtQM6ObQmaaRu4kRBRBy2/xtVKPE2BPBFNJbAHUSWcyJQ6Bb1
         vqQG4JxjiXl+HYhfNh9fTlycx5SI+91VK01G8WrB442JMG0+zGDCZkDvb9CyuJ5Hw8/g
         fzeDlNO4jC8y2W6S98tt81TRvDM/Aqu0+XHXxZw763aAO1a+/RDhz9g4kAdVGnpP+JUB
         XW9ssa0vhi42CkRX1xbLzUfGP7LgpUzPYEcW7O/uMicKuEptTdKpoCQJX8NNgnUEfhSG
         6ZLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769018283; x=1769623083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=9dWm5k5tm5kK9MeyjS+3N67tX+D0ZnKQ2qzzD7uPURw=;
        b=RgsstUr1tDwgJPT9UKPOHs31lkjzs7lXjyD8pDr/T7b/98k+mVJ7OXl0RgfRIFf0fX
         lQIy3UMMoagnGCoZCmd352TCZWcNeK67SNiUsIpOa8yRSYQjfjYMQwKc0cfH0JvtIOoj
         6ZsecBPrPYuXyUVoCWUkP3zP64N9lkx3dBtxFjM6g16Y0QIh3iLiVmTsi4oAUrrtT/xN
         rLqhEOaItUFb4vWmqygkQ1OdMpHuDgPu7B3zQBg3tbcZ1I468CESECvAPBiqrs35+5Ya
         CZd/hZ4oPCE6GVSd8pt2MKxyKelsEwoSz0heCHkPyevqFlCi0xJ2X8Z11c1ubvW1cxfq
         iXkA==
X-Forwarded-Encrypted: i=3; AJvYcCUf68FDoFKL3uulT+nTski9/8nYGYFtOz8ruI0Sc2UH52InYnOk9g9iXo+cl7JQnXTMlyTF9w==@lfdr.de
X-Gm-Message-State: AOJu0YxR6BEfEBrJlrsxuJd80ZyNyhZj7XTkZV58ldyozRhlDL/TKCR9
	Sq6yfRyP61M6h7CGaDcTz5NwRSwRxNPUE4qVM/fWLjaY2+T/LvYkQBfr
X-Received: by 2002:a17:90b:4fc2:b0:34e:630c:616c with SMTP id 98e67ed59e1d1-352c4055083mr4213138a91.31.1769018283276;
        Wed, 21 Jan 2026 09:58:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F25pM22RMQ5K0VGf8RLhHGxRlAY1MPxcwTENa6syhZww=="
Received: by 2002:a17:90a:f3d6:b0:352:d92f:cb37 with SMTP id
 98e67ed59e1d1-35335c304eals18832a91.2.-pod-prod-07-us; Wed, 21 Jan 2026
 09:58:01 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCX+LEquizU3ODpgyLDJ1VfbEZij6Fkdf6JLEHvr5kh75Ov3LwMoqHXLMi5KBUMOw7AWqQopFrYZby8=@googlegroups.com
X-Received: by 2002:a17:90a:d887:b0:340:ec8f:82d8 with SMTP id 98e67ed59e1d1-352c3e49d57mr5490512a91.12.1769018281631;
        Wed, 21 Jan 2026 09:58:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769018281; cv=pass;
        d=google.com; s=arc-20240605;
        b=dA3CwAStY4IXYmr7GGCyEEhunscVTmsYr8Z88Bpt/DNu1BsRsiliTTC7wIrmjztPLJ
         fRqaOG8CWDucVOxqwcsrR2lsVuDiNIh+iYq18K6dLtWiIPaOfLKBfjvVeEdNFa9C8lrR
         0pk5oJ6Q2Ey43yHm7ka0bs/0EaNYYlegF4wqdDQc4on4hrt5vPB8n/v1hrY3Xh//b7uj
         ajLe9T//z7XGRA9ybdodnwx5JelzWbxbOHZr1uilDm5iL13fre2cFQjdTPnaFjKLkQ9N
         BWb8TBK3M4hlajf/0ZazbUx7ceiVvXfENl2pXGzkK5vQeoYMP6uJNk9NqqAhHmkpsVwy
         zpdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2e/dfKIPzPxfuYZfQWM3FRBJx3bq+IVKEQQ8IC7MPec=;
        fh=BADfM2a0KMY5T7wBRbPiMNFYOg3m0fFQ35kxJNqC2kA=;
        b=bwQOMYmNUSuuHsGGPnE0Aaf3Jc/LM0QGLl3v9cBbUM3GSr+frCJozbtZe1GEXyDL9O
         NBtUEc5m5L6CmUowTuRCHZ495DQ61atmHEFMKGJ2lw4254WnBeYBrHmr+GjFmXm+c8P6
         zgyF9NfdfsDNrvJ71YD4oOK5ijvq1vS4jhPJL2BMr9Eot+FIeUI9fCGQj9m3t2FMZmAy
         aQP+0u0kgmUHZ45hiXo7trVeZJ21DYOvWHZ4Tp/zQqWF1QRr5GRuKZkLd215dceuvEbi
         iDToHCBUHAye+GD1vDTjQj/KSIQZT/viuayVxRV+k1kMnNYFDnQK5s+LU3F8TwjsILJI
         5KJA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P7Zlabya;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-352fb00ee4csi33959a91.1.2026.01.21.09.58.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 09:58:01 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-501511aa012so13491cf.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 09:58:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769018281; cv=none;
        d=google.com; s=arc-20240605;
        b=gf0maiAKQG3whYTqI2Otz97MSlm5pi/T4nd2QkO5B4oW0/gqAwZj6dfeL4zIutyR1g
         xnciv/wI0V55jO73FKlnMzstRo/ZIoUz226Dh+BExKCaIPft0WVGa2CIzYbjHavLynCC
         Gx7DT7ngyDqdAudpaOj2f9PCitgRc/X1jZKjye+uXBonWDLK5y4qg/tx8tuayN361qD0
         sMX3Pj0+OSC/XNH57+c0EhVQapB1zajJriBcfjIneZWV89ehE4VHaPW3VAri0z/d8ImU
         B4uekJRRreOlqRiqvc8BA0PN6mD7zVxdgokzf4ev2JA3Ij/i7nLbsNZRTvKfSbRJ2Pgi
         qTbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2e/dfKIPzPxfuYZfQWM3FRBJx3bq+IVKEQQ8IC7MPec=;
        fh=BADfM2a0KMY5T7wBRbPiMNFYOg3m0fFQ35kxJNqC2kA=;
        b=dOPLYB/UK/I5R0zRb6Mz97TgO5+0lrqfF+16ggSRApnST6MVwK9np73wnfpm/OU3/D
         SMFGa1zMZdBSC+Q0OgBeqmQVc4t8eIMQDuZEL882+sqozx4NtgCjYHp3rLFfV1PHH1Po
         5ZHBRlbZV7DROyHdYZuuOy4IqzoQ15d+4BBk4v8YAHLU0XGf5HRz3/xSnXZOWJYo/4HA
         sx+Uk2pGKGpJmHK5P+vjuN/V3J1JEHwRHlAfp4bag5vdzqoMMtN/YgtJPObWocxZsjw9
         /Ea7dy3u0AgoAeEljPp7tMWtenRtrqadaV1zb9v+dWyKvhhLm27zYnkTErA8g9prU2q6
         Us9w==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWj3dVOkeWBweyrn1YURwu9jo/KZKEsGLqR408ANs/FQOuXlsX9w1W+p45Lfitq//aamj5dzEcoW44=@googlegroups.com
X-Gm-Gg: AZuq6aKKBtQmhYsFMCsiNQZtLd40EqQagCKckWcoRBws/MR8eMiJVHiti8m7Vkcc8vm
	96dKbgDxEUYGG38LpB/3D34Yvv5vzdFeI2SF9GFWqXHInh1JPECHPVuCzw3Km6Wl4u5mD1bhRz/
	DIf34CaNaskpDd5Btw+iZQzrTo1If0pQbM5+ERNK4PWXizRXHaIww8rnp7QYn5xDgv+fmZaZLqK
	0jiky8HxDz3ocN7F3rl9dGRr2647Xib7W8muxcaLd3Otpv0grc+cicGyOn0lc3Cy3n7YnEZcBbF
	N8a6GglNjyxluBE+yF5dxzA=
X-Received: by 2002:ac8:7e8c:0:b0:4e8:aa24:80ec with SMTP id
 d75a77b69052e-502e0c62ce0mr15215251cf.14.1769018279867; Wed, 21 Jan 2026
 09:57:59 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-16-5595cb000772@suse.cz> <v6govsosryla4nzgzbfo3eeiziabn2tdprzhg3zcpoxkxq622f@2ra34j7326mn>
In-Reply-To: <v6govsosryla4nzgzbfo3eeiziabn2tdprzhg3zcpoxkxq622f@2ra34j7326mn>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 17:57:48 +0000
X-Gm-Features: AZwV_Qj7XuXMulWBwzFRyGRxqGQl3pWQ5GGLctP7N8bmgHrWL6WoILa1XS1waUQ
Message-ID: <CAJuCfpEPX-jjztYVRNX-MzQYdcf9fBrePf0zbhDJFKaEvpcp2w@mail.gmail.com>
Subject: Re: [PATCH v3 16/21] slab: remove unused PREEMPT_RT specific macros
To: Hao Li <hao.li@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=P7Zlabya;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBKVHYTFQMGQE2UYUGVQ];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[suse.cz,oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,linux.dev:email,mail-pl1-x638.google.com:rdns,mail-pl1-x638.google.com:helo]
X-Rspamd-Queue-Id: 40E175ADF3
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 6:43=E2=80=AFAM Hao Li <hao.li@linux.dev> wrote:
>
> On Fri, Jan 16, 2026 at 03:40:36PM +0100, Vlastimil Babka wrote:
> > The macros slub_get_cpu_ptr()/slub_put_cpu_ptr() are now unused, remove
> > them. USE_LOCKLESS_FAST_PATH() has lost its true meaning with the code
> > being removed. The only remaining usage is in fact testing whether we
> > can assert irqs disabled, because spin_lock_irqsave() only does that on
> > !RT. Test for CONFIG_PREEMPT_RT instead.
> >
> > Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> > ---
> >  mm/slub.c | 24 +-----------------------
> >  1 file changed, 1 insertion(+), 23 deletions(-)
> >
>
> Looks good to me.
> Reviewed-by: Hao Li <hao.li@linux.dev>

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

>
> --
> Thanks,
> Hao
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpEPX-jjztYVRNX-MzQYdcf9fBrePf0zbhDJFKaEvpcp2w%40mail.gmail.com.
