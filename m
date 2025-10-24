Return-Path: <kasan-dev+bncBCUY5FXDWACRBF6K57DQMGQEHZ5JNFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A046C0818E
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 22:44:09 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-378dced2d53sf9832051fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 13:44:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761338648; cv=pass;
        d=google.com; s=arc-20240605;
        b=CyUKExlENy0MAtsOzAzLDXx4tFik68dZYtVWU7OnX2U5shJYDYsHAI7vNYGY3e8+5B
         KOBPd5zNP6vawSXuYQQ1cUAd4ZuUPMcxNVwJv28GouDvTCXauKQ0nk/UcCDZMAMTRqZw
         gT7Fj5JZUzOSJmJbmNbitiAX+a6GieUz7Qa9gHXj8A1ADE8YtWB5S+Brs/efxdMN3iYh
         1+qEES7+BWDDwD54H+9ybIYd+40qqtIITZ8uYZM5ewFtTDI5ws8zfZeDVDPFScg91zuK
         YTg4aETWlU3KZRQaiaQsYkHFITDFqGGXvtWVUB6f9AJLefaUUS9hNVHKzmVf09NuMXTh
         4rmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uH3VRIbaQ5vub3Znj1nSsh6fua6aMYzuE/0i+cY4yAI=;
        fh=ScrMBHw7HVd9uWJ6h/5w2K7Ek6Kx5QWRJ16P1i351Qc=;
        b=lEcG5AkNr12of3eCK60nk5cYrLkVMAN3cYhas+wUpHQ9SS6ojhx9bMD1VOdEVGOTDv
         A02ewBlykrZ6U6tWCmQlJDRmiUd7rDtCTuD8MJvaeSC4jlOER0TeKbCpIB+LKMkhqJRs
         lFqpoj94jo4GMWJk9xBsR4SekjSGkgAO/cLpBFxyasE2QlGW3RikR7V1Wf3U6EN9Af8r
         3Yq1krAVbqFA8uOMuLAUm9AJE2NP+eGXNzt63spZsCTuOD5sXirkoZyEurxNLW7N26qL
         S5RLzDAwZAWLraw7TrAXS/Fj/MYHR5+qoQqGov7XRnC4fpSCqY+0hwqhlp1EVeC2oNJO
         ORvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iKFFgLZ8;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761338648; x=1761943448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uH3VRIbaQ5vub3Znj1nSsh6fua6aMYzuE/0i+cY4yAI=;
        b=EeWSD/PltVb6c4s/0pu+GeB9I30kMR9zhyHhcBB6eiLtmjciDoBs0rtA1GNJTnOvYH
         1B6JfU5zznReqfLCEuD3VsQ2dN/7ullh4LQU08QzlunGXmrmlooJm4mqOHQiGjew3tax
         qTBCY4Lr6Wwc+iO9Z9Mc9w3vkyJP61pZ5YSayk0RD6PquPGV2v6/WwmkiuXEhT5jYOvp
         5BAr/6OEkmxkq59WksyZoYjcVQ5fSb0YGr5WzbbUOg56ax9TvFURTrnHn2Qodibx+Klf
         Ll8bbo3CZUSa0IBKqYk/3+DN8e8D2pjNd9FtK0zUIKblFmIETS86jDNjIUwQG3Ret9iL
         pnGA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761338648; x=1761943448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uH3VRIbaQ5vub3Znj1nSsh6fua6aMYzuE/0i+cY4yAI=;
        b=KcvQYeY96hKduP06ViY7vCVGPzRS7VMqPRZBCETkN3gojLqCMUggeh27t5eyMaktm/
         4R8bg24GGtX9bJByFCC2Ssy1dXO+2bbxvS6iSUhTfOjez9JsPEaEU3if2SPBlWtUZvDJ
         pUhqpwQDW7rs0Q177zYBeMAGYR5Dnj/GA+s1I0MeA8LTYA2vCispifTQJeaJ1/ntjSpI
         OEGNLlGbPgIAefSjEZHLJDNci8AWOfYdRftbEZWfDDoN1HwPCt40z7MrfhduvJreysiN
         YSKBeYBVAwmbGPFUDTbzLs6wtulQjWVm1Axo7fLo4m3gl7AoyOM+PIRmJZCl1bSqmsjw
         slSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761338648; x=1761943448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uH3VRIbaQ5vub3Znj1nSsh6fua6aMYzuE/0i+cY4yAI=;
        b=X7Qa6au9T+LTCEHUPCslIZXk1wjkK+2/ngxhAC7U1VfeKkEdW2SYFpZacDxiFQ4jlW
         4Z9meEWOPZfwlUcfQB6TEO1cExpr3N3YXI4W+706Dtt7NczcKoVqqkaQMSYH2QemX7L7
         lcyXyt4p5k4LFCYJMVOvzRCcM0BKjIVmRTyVjJMY+bjrrHvqBYJLPXl+0eQZVowfXCQK
         lMmmXdv1oG5bIKsIV6zatEpoD5i4GlNH2KusSmq9jNeLDqdAevzD5V6uREAAwP7PbCSt
         luuBSwT/pMPD/6h2S6s6/bdDr7IMq/Uvz7sA9jfBvIJ5ED4wIapmUcJ7/L/Jd9dOuQvJ
         ax2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtUgb6f7DAYT9vA+dWSLziBrl2WOncsQAxgVwtgDwZAD659lHbL2eMyde/oc8qGIAHIH2Wcg==@lfdr.de
X-Gm-Message-State: AOJu0YwFWD1JWWgHtSUdqtaojLKmsSuvaO5SHUa0451pOv2I6q8Nn2zs
	ehtxyNRLhxrWes8m2XOoZBf0dBLYzV8wvp4owx1kBM6fKGdDpAtG4YV0
X-Google-Smtp-Source: AGHT+IHd6Y5SWtIwRDhd19ai6vjT9xlUyUDFTnl3KFYc+H3DElmu3mD+zGCtt695txYEWuCzkzEQyw==
X-Received: by 2002:a05:651c:1545:b0:372:9c25:7a94 with SMTP id 38308e7fff4ca-378e43c64a4mr9919431fa.41.1761338647887;
        Fri, 24 Oct 2025 13:44:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YJIgseznNrEsLE2FmmBc0iQeuHW2ENjzsZwr2f80Ti4g=="
Received: by 2002:a2e:8619:0:b0:372:9093:f49f with SMTP id 38308e7fff4ca-378d64cc268ls4138281fa.1.-pod-prod-02-eu;
 Fri, 24 Oct 2025 13:44:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVeVu7lGyGPrcw8iZ++kFxK97aQmucsn/aovx0ACARjk/jI4jsYUAeQqNWKedek1zK9mmz8zloohc=@googlegroups.com
X-Received: by 2002:a2e:a9a4:0:b0:372:9e15:8979 with SMTP id 38308e7fff4ca-378e43914bamr11254321fa.24.1761338644675;
        Fri, 24 Oct 2025 13:44:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761338644; cv=none;
        d=google.com; s=arc-20240605;
        b=V4ty2yhJxg6dUl8sEC1toaIBsbSZZ4sIMPhrnIz03mAa6tzNDxNw9UF1Ga1T+sAZFa
         USYPIwhVAMYccu6gbw/EJXJP/DrQSqzEas/viSkp1wqZha1CjAp4aDdPs0/dL8g+bH6W
         RpesXSYyRR/NMgdtUtNdipVvknyjxczN3KNy6ZZrfiguX3AyudFsJ0AHgKRhyIEzSH3k
         uX1Mmedstqa+CqKaj1h+4U5BapPxKlQ03PhWGdrl1DZT8bsQVbRz8nfb+vwrhrh1gjFa
         RNEyT43d4vCn0pjFO1SB9stuRUpzCwOWBmWh9r3YJULJwOl4fNoN/qD98M536WiUzY8B
         1wiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RxHcVaFJP8LSAUbqjjuozojLxS3r7R2EKYoJfzV0av8=;
        fh=rMc8n1G1myzjkad1dQK7nfHE/OR1A9d4bG560vjgDBw=;
        b=JdWxlO3bo1qyQA9H31qt4HVlcWtujSAUvyhh4u5oVAiHlsuv1j/D5yUFk4dQowrCg8
         kQuQsC8ixtTTSfk/DXeuNPgEuk6YACQPaj4eXL0qnK7ysXfbeiuHBBwrOC3Gj//nVxMa
         CWx0K8hov5QYKn1KypYAoLgmcEvry6Zdj6VX4anEmZ4SCW4mn6XWT9JqDW2rLQkL1fYa
         Fgd6GAMAdT1JscQgvgvZ8rI/KyD/nu1f3AdHlGWjSljjbINAc8A83706BPuNXfja/BxZ
         +l0slcujAmPi8NUhOfw8y3yz5gyqjCgYAfaie/Pm7HJf//oWLW2OyZDhPeeZ2DHTMGnn
         6T5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iKFFgLZ8;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378d67c267asi1087551fa.7.2025.10.24.13.44.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Oct 2025 13:44:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-426fc536b5dso1804490f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 24 Oct 2025 13:44:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVwE7JSBFYPVehDVmIr7L/fwGMj11G4Xi6CAcOYOIls1w1CzfIX9fMB8WhNxulj/cE8m4uUOuQAbOs=@googlegroups.com
X-Gm-Gg: ASbGncsrM5bLy+JZDDoYaDhUH5vy2qgmDpfcJfB0fWR6wRn5nBkdNVcUyuMz5FTAGwV
	zcXU8ULX3g7TyNdlDExqf+Z21WXx0KRjl//ZIpN4Xt8QWXtt+tIKHD+ekaOmf2MLJnufkMgQmBE
	mPLpSBh+P5UDFf3GaQEHUimym9O1geHRJJY6NYT7Did/8TzoS8ywo/y+9mcfxp1mtAbLxYJ5dyp
	6es6pWRJyn0oqi3Tu/EH0UbbQoU1ll9OD2PqycnALJ6Coy7kLPJ1LTSoi7+WrDaZG4Oz4CaxDoQ
	jGix/bT4P1vF0p7oGDH3urJzME0i
X-Received: by 2002:a05:6000:26d2:b0:429:8a81:3f4d with SMTP id
 ffacd0b85a97d-4299075ca93mr3213632f8f.63.1761338643874; Fri, 24 Oct 2025
 13:44:03 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz> <20251023-sheaves-for-all-v1-11-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-11-6ffa2c9941c0@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 24 Oct 2025 13:43:52 -0700
X-Gm-Features: AWmQ_bnqGo3VhvdnD4VDhLrtr6dWJQ16k-K7Ue44kfB0ODJ6fAEdUY4Nt58fKuE
Message-ID: <CAADnVQKBPF8g3JgbCrcGFx35Bujmta2vnJGM9pgpcLq1-wqLHg@mail.gmail.com>
Subject: Re: [PATCH RFC 11/19] slab: remove SLUB_CPU_PARTIAL
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iKFFgLZ8;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
>  static bool has_pcs_used(int cpu, struct kmem_cache *s)
> @@ -5599,21 +5429,18 @@ static void __slab_free(struct kmem_cache *s, str=
uct slab *slab,
>                 new.inuse -=3D cnt;
>                 if ((!new.inuse || !prior) && !was_frozen) {
>                         /* Needs to be taken off a list */
> -                       if (!kmem_cache_has_cpu_partial(s) || prior) {

I'm struggling to convince myself that it's correct.
Losing '|| prior' means that we will be grabbing
this "speculative" spin_lock much more often.
While before the change we need spin_lock only when
slab was partially empty
(assuming cpu_partial was on for caches where performance matters).

Also what about later check:
if (prior && !on_node_partial) {
       spin_unlock_irqrestore(&n->list_lock, flags);
       return;
}
and
if (unlikely(!prior)) {
                add_partial(n, slab, DEACTIVATE_TO_TAIL);

Say, new.inuse =3D=3D 0 then 'n' will be set,
do we lose the slab?
Because before the change it would be added to put_cpu_partial() ?

but... since AI didn't find any bugs here, I must be wrong :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKBPF8g3JgbCrcGFx35Bujmta2vnJGM9pgpcLq1-wqLHg%40mail.gmail.com.
