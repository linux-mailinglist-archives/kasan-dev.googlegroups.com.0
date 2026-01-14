Return-Path: <kasan-dev+bncBCUY5FXDWACRBDM4TTFQMGQEPPA26KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 6052DD1C42F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 04:31:26 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-6509ad48ac8sf1753984a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 19:31:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768361486; cv=pass;
        d=google.com; s=arc-20240605;
        b=JyVry7AVuJpL6e9TRX6/DcUvLrrjZDX5vheEpCCHhTUoSuBhRWz2djgROd7xxvrwr2
         hf9/0/XTF17dvqhGIV+ST1VLwqw5PSx/E3+FlNjBLGPvekUN23+zYtNWW7st5VoK82lK
         OIN6YCx/JPFeShce/6zh1Txqdi9Zgwcv7bVQeomK+RbyJ2UNdhVhSJ0fDYzGK+PVIAgP
         A5TjZqFukshqBBS02s/ywcHiAGBBcphujI9tq11eorglP9H1A/g/g5lopmFN2hcSeSKA
         emDGjtEkw9ctJfw7f2yydkgoSoZ8jCyAoua0Sl1FL8nKWEyh+eAACoH/sOnJdPaiMHGs
         Sxig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CCbpZHBoq1AiVKGkNb29ZuM6RbD2tKlIf6vrlBcMRMA=;
        fh=qJoOfCFX3RdkQurD0iI11Ceq+b7H/ctUCW4hFGBfgE8=;
        b=kDAR7uwDBdapVxELKL5I+yMwlcWU4/qed2hCt3oT8z4SdDphwGWD9MPJu1lFmmqtdp
         7FO0T+rh0ATAuN3NyF3EW9V9oThmtGtZCg8zD982eL/37oHhyUVcAEhH7fdd3HnaalDV
         jLTASYLv4FFmma5jRR+JoT4Pwp522LHsaQ+xgQNF041LS85yh/n1g7PChSPui9eMfBQJ
         rOuoLWCZlB6Ja5j2kOCfrEYkaF6mROFecM+uNaEZrefDZ2pa2Jv9pZUAPZWZKCpYrwO5
         GN3CZFPoWpK7K44D5CXAIUSVWlNJ5o6JmueAmkCgHq1qML1X8CDHlx4vrBsyJ8fivKjQ
         yAWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ge5jHLrK;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768361486; x=1768966286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CCbpZHBoq1AiVKGkNb29ZuM6RbD2tKlIf6vrlBcMRMA=;
        b=QDo/O4FJLZCTme1teab3s+//xr5fEjULaiAd2YEPxFYL7P9Z/imlf8QmGqrB+qnpRV
         Ul87/V+oVZwfyHF5b8TmKdclTWp6uo6G9q3MhDBy7yliLUbwbP3bulSQNEVMVwBgR6Xx
         YKAinZu1VNFdKDQlW4PBkV4WwzLhtlwuKMpoAyk2AXUmXE9AioLfQc4TTA2PgkJ57Dhp
         P3E0gGrHyxFN+yPZv6UiaszruA2zzIovqFFBnsw2EYz08/kGqmY8etvWbe7olt4lEsxK
         Lue+mGFTD+XMLXNHI7/s82BI+q6M3QySQbcHWm0rm42UG/LZNKliRvpX041H3/988nyD
         /p5g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768361486; x=1768966286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CCbpZHBoq1AiVKGkNb29ZuM6RbD2tKlIf6vrlBcMRMA=;
        b=j88UsmDANkBS/T1c0lxYWFbOF06VL8pEpUAlifgJtjwIa9XDsr5i6UuofezQQpLzUK
         RQY4+lJXXJjN+WYi1NyDzA7kDsZkR9MK2n8zTFDL4fpda+dD3UJHbYTHMzSj2Lvf+Obd
         /Ei7lENKbna4NgCHmgvErXfICe+q52jGGXGifrHAqs+HeWJpLm2juR2XXrpx52aPH3MR
         g6oXrkVF0N/ujqwq8/xUJzjG1WrDvDVpsBkG/qGnmmi20rTixEKl+EyqreRL0ikZQSR+
         38RnNVxlSiHiX0D6HJybyOGPO+A0Qswpi/v5fQppwqrJpb/GWcYwiRhE6PCcD3lhstzl
         Maow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768361486; x=1768966286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CCbpZHBoq1AiVKGkNb29ZuM6RbD2tKlIf6vrlBcMRMA=;
        b=FwlG2wf5aXfDivAQ1EMJGuebUEHJsy/IDBwoJfHGWbrMNLg0Zc0OuJaWrWuJ/+tUIF
         /88ByN2V0raq8dTaEhz+K2vtzI4zleraragPvxt2xitoTRoISX2Vlaem32MFzKvCSqRa
         pDd2CpFCHNXsbPNQU51Cs48JmxoWvNcg8r62a3VZf8eeD0XocQnXWFeBOSAsk6U53BZR
         Ugp8tYifBQLY/yRhWwTVSZc/kbLKyjO5jD7RYX5AdBrlTbo5pX3uFCGqn87pcVGx56QO
         Mma7Mua+eu9mUAaBAecFUvCUX6/bpy6Pk2a37aYo2/MYs2imvchsmmCBlSZblGoxCSw8
         RpyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUoUMdPbHh2IDxB+FLcg4rw2OdykJLpoCprpYWaCyqOHWFEjzIEy4IaiN+YQtekrLOD9Dk67A==@lfdr.de
X-Gm-Message-State: AOJu0Yx4oAQ1cayL3ZTROQ1Vn7Bky2v85oQouBaNnEo3rSeLZKIryJqM
	O/YAk4ngAOQahsbbP4wlR7qUs27U9+lIfwGd1rwImtZOFUc96eBG23y4
X-Received: by 2002:a05:6402:1d53:b0:653:e85b:7729 with SMTP id 4fb4d7f45d1cf-653ec4480d6mr875383a12.19.1768361485620;
        Tue, 13 Jan 2026 19:31:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EnT+cbcj/wo5x0WU2BrAGbpJdt0Kaj2oHafjA71Wml+w=="
Received: by 2002:a50:fa92:0:b0:64b:aa45:7bf6 with SMTP id 4fb4d7f45d1cf-65074202c76ls8787023a12.0.-pod-prod-06-eu;
 Tue, 13 Jan 2026 19:31:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7ibfeFt8WOilgwzn0ijlIvXachEi49Y54JYoJlxgoc8gJjtpZ5bF7eveMij9yC3xUBbfvY7N0EXQ=@googlegroups.com
X-Received: by 2002:a05:6402:280a:b0:64b:5abb:9be7 with SMTP id 4fb4d7f45d1cf-653ec458ed8mr888870a12.23.1768361483020;
        Tue, 13 Jan 2026 19:31:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768361483; cv=none;
        d=google.com; s=arc-20240605;
        b=Z/gR/B+s5lvmxjc+iwaPcDNKEj3DuNpWVrxHN6DfUJtRIrGyNf65bHeQZLXHJGEhnm
         pLqVC4Xbm5sC/jrYEY09EIrn+iHCVtr+sEZAdjCIiihhpDrx2Huy7TIN2xnIMmPsbHQ5
         9KSAF6KQ3uj/Ob3xiI0RVFKdKcFPjWBRHzuYr8aCGqQCoRY856yAsWSPM2HgZyUl+ZEn
         N6cXb3+iANDOWymZBVFI9jTmhRUcPwz4J604TExDc69FiLRuC5jdWnSlydWHRJywTe6b
         3QvAGpGhQVg5+FUioc+iItondCvs4rvbN0WsvABsipxE+hBiINH0F/VoWyWC0Bkbcg6Q
         KJvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tAwkswLSDvceXj/iX0pI2u7qJO+mp3M2B3KW95gBNSc=;
        fh=GPoiAVKstrl83Zd7vfKVoY440V/2KNrXsiQmICaisgE=;
        b=Qp/4MEwdpEGz22hzjqxJ3KcEtFvs8OsO9YSHeQV49Fd0ExKpTYxwwXgRt8HUCHJio0
         YWyKp84o2X0KlOdKfBgNDILdIt+2k/QdQ1/gKIWopvMpT+VrR76wPPgWBaWgDghmZTUo
         LJyB6oCYEMkt4vFa4BE6GCbmkTk+qjc7aaHSyhofG/4rnF4mD83RNfvdYm+cbEl1uvR/
         E0ldZlsWhVYh+ug6g1wHrLy6OWrW9DyFkmb9gYb+3OA3z2pU2l2C7zvkKBpH7NbLbt60
         rwQNzeCEiBAS8TuLj1FBG+ZyHer+CJgRKx22LmwgjssWvLZ6VZaE3wSoLt9mlGM+ZL6g
         yRUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ge5jHLrK;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d7230a5si469903a12.8.2026.01.13.19.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 19:31:23 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-47edd9024b1so7443585e9.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 19:31:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZ58d2pQ6MMQwa7I6J7S3WiYtMYo5k69iKn9dxMkffeEfYV25QjYAADkDa6n7JZ1ec666Nb+VJS+Q=@googlegroups.com
X-Gm-Gg: AY/fxX4smslEFxz2z6pQdGsZ0lA8lBUY6fEZhKYRULAdFcbuSp4iu6kNrgSP99aTtNo
	WeSyiyUW1F5HVy/bYWROiLrsmh+IZle7tRBJl+s7+FlmvJvClSXLpRcXYnU+ZIP1Jwk8ue+ALsj
	jT0p7e+Wxm/btfdCy4yLMGWLWb9sCok1RL/GkQmdWLGP8UTi9/jqVDX6dVlHm3Zto1wVG3/0PnP
	lpWPNsR+onDkTMYtUizEAZ3kbtOPdTAUoXUj/uv1GUVdb85uL2IC8Rq7nUvPOVEfxLB4cqmVBeZ
	o2ECQrf/A1XKlLE6kCrPl/JEJzlu
X-Received: by 2002:a05:6000:310c:b0:430:fc63:8c8 with SMTP id
 ffacd0b85a97d-4342c54759dmr1005118f8f.35.1768361482534; Tue, 13 Jan 2026
 19:31:22 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz> <20260112-sheaves-for-all-v2-13-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-13-98225cfb50cf@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Tue, 13 Jan 2026 19:31:11 -0800
X-Gm-Features: AZwV_QjU8IHt4ADtGwZuCMWdsEN668TGd1jbbhsvRKh-PS7J4GcDNvMn4EbhZYo
Message-ID: <CAADnVQKBt2xmqs+o0onUwd7G-0UDbE8LECnkJJUCVbywAr2tUg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 13/20] slab: simplify kmalloc_nolock()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ge5jHLrK;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Mon, Jan 12, 2026 at 7:17=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> The kmalloc_nolock() implementation has several complications and
> restrictions due to SLUB's cpu slab locking, lockless fastpath and
> PREEMPT_RT differences. With cpu slab usage removed, we can simplify
> things:
>
> - the local_lock_cpu_slab() macros became unused, remove them
>
> - we no longer need to set up lockdep classes on PREEMPT_RT
>
> - we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
>   since there's no lockless cpu freelist manipulation anymore
>
> - __slab_alloc_node() can be called from kmalloc_nolock_noprof()
>   unconditionally. It can also no longer return EBUSY. But trylock
>   failures can still happen so retry with the larger bucket if the
>   allocation fails for any reason.
>
> Note that we still need __CMPXCHG_DOUBLE, because while it was removed
> we don't use cmpxchg16b on cpu freelist anymore, we still use it on
> slab freelist, and the alternative is slab_lock() which can be
> interrupted by a nmi. Clarify the comment to mention it specifically.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

sheaves and corresponding simplification of nolock() logic
in patches 11,12,13 look very promising to me.

Acked-by: Alexei Starovoitov <ast@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKBt2xmqs%2Bo0onUwd7G-0UDbE8LECnkJJUCVbywAr2tUg%40mail.gmail.com.
