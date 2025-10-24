Return-Path: <kasan-dev+bncBCUY5FXDWACRBDH657DQMGQECEDAGMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id EA336C083F9
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Oct 2025 00:34:54 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-592f0214ee8sf1958512e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 15:34:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761345293; cv=pass;
        d=google.com; s=arc-20240605;
        b=gmxx7+cDbCpDudWg3FZmdsLV3SkZGuJ5RF/zxPbo9La5zAu2eiJ5EkmDsaYK7ZLqBo
         Nw0GXToX1VCaY3dw3WOtlFLfjcfZMOgJWHsWt7oZ+7obLyYI6+voB0SXBTQuauk5W0c1
         vQmix+Fi+8ZDl0RKbWZCRMLk30Bps7gTAbW5juzRYrb1JoBrBffeo9K8+GHfr99a9Cs6
         5CetdI1sGYAt9R48j1lzb5jBQXrBALIpoktAizl9DZhnoy+B/WUL8klkyJXCXDgW3v+a
         UIMXvCBvJgM3TZ1gFyxdAkLCYCULd1L3ErJOm8K+RHuSufVgwYZkxpXktDRuBChnJS97
         UmEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Ar/LI+PcYflAK4TZeO0W9g62phuYKGCKLGofpyT21yk=;
        fh=ECiloHMjDwqTbYkSDiVfkEot7oRgfFxoaofdaAfD3Wo=;
        b=RfNu02bv8IcYvr9ABzUCKfjjGkZZGL4jgvi6gyisWL1rsGqEb5umKMldF8wH7kzhaj
         H0mvDNH8HRuUr43o8gdI9DbVF+clru8E/SyVn5IK97dPduThQX3Hy2/hZYHNxyUzcDUy
         7wXHWrg1HO2QVO+bLuZGPZ0NZ5na5tboMTgzvRkWLysbp1AIf2vHbCj9h1L8hoXrThGk
         7CMjXv7KbzXS0cQWfIMtY95ibnmWEjQxLH1GuKuTc4e3A+D69ZXbJ1cgyB+lmvFXEPpF
         583LPA7cWYFiyORmdGLln1BjBncgeMxeMYCHj2rW/C06OmcTQLIfQSabLAe7Ryw+KiVz
         M15g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Lc7yveoB;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761345293; x=1761950093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ar/LI+PcYflAK4TZeO0W9g62phuYKGCKLGofpyT21yk=;
        b=PbBrCbsmkkJwNvzFt87UhG/qGaAiKkhw+H8pyCUEYCsOlVALFO2Bh08rYCc9Dt33/e
         CsFLTFQSNk6elmfY95iYL8v/a4J4vXgFsdkOfuRSFWONd6hX6t0321+BkiBdCdTAiVQW
         I9bJ5dJfZtCXGT3X10Ocva8rZ9mIZ69T/bPTo9QiS3Ii7YZJhxu6Bo168VZbbt5AQi9a
         UmrsIb+iomU4W4y4WpKAI0qTdThpxZv9PLJZUUa2R3Wn3e31xsMaHBl6IlJhKZi7yg3F
         7PSI/zZInPY4IUZeVsHNK5Rloo4Vho8TmK0QAwclEB4Z7xX+xPAjkLWCqOAf0AM1GmCc
         A7Lw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761345293; x=1761950093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ar/LI+PcYflAK4TZeO0W9g62phuYKGCKLGofpyT21yk=;
        b=HyQrFQYeENh0zwqL7PwTMAKwRWFaWfk0+I/K/hY60AptGlZdGQEIocDNWpNWK5EOCO
         sKOakUfuBudkj9Wg0p/XIKJMWdABX1gT6ua7vAKFj6NPuSUBrDGvQFp//krb8hjzJdCR
         ewvqX6+Agn19Xxyj4IiD3XHE2/BDcpH+4fiwQTPOLiHT3rXDZkPNx/o+0GW73nwmJiG9
         P7wUMqouwkkoDlvCNqfuQebpX1yhI+k0MA4ovuN4hwhsvFl3RhW4NixCy1dWwz6PRXjE
         P8M3qbNH9O5T+7pF+LYNOWnHsP6ssxVO3ktIXIFtEsxZh861Qoz5pR+qY8O3zWJbkMEy
         kpPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761345293; x=1761950093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ar/LI+PcYflAK4TZeO0W9g62phuYKGCKLGofpyT21yk=;
        b=Yb58B0IJ7+yagLRiQ87glZNjhau5lmx+NCEAHUcNFLerpStGNOYuAnrDj5/6xUczLt
         a26TlDnw3e1WU1lZgOgOJXlfrdwE388Le81behmi8v6zwJsSnpE9/+wshYaKg7yPsJbv
         cDqfjAi7icdXpY84OJDtTIH6ZzUag/zLI1hvaiswKSWGa+AFH2STUScF2wG8OGLkskk3
         21bl2I83ysQmRx/5F+/SqkkiaVQ2kNDOeNDrJr7HzM9jA0NBfZokKAUXxxCAn5eKaND9
         EvZwOGroQ9noSVX6Gd7KJnQwzJflfg1qeBTWiqWyXXfrfo/rHl9W908pc8yK86RVZ0K3
         ImlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtwne7gr3zfCPCmkfU1z7YP9TXwK5ZiI5eqfzwPWGIb/RSIb5UoAokLTCeKkkvDP4qgN4Irw==@lfdr.de
X-Gm-Message-State: AOJu0Yzy6uK1V4QiWrIWxDv97hwd57ugR1DNHbgHEeN8GhseXDO0dfiE
	hesjnkwcgwLb1E8+D6KhiADuGaM9G15LgxKMkT8Vtx1HfT5aEv4w/jVU
X-Google-Smtp-Source: AGHT+IE26JtTRs4ihD9Bm77nDz29NFEW8enMkqUGMsUUJiy6O6TRaMhYiCHxIEbwXpD8b62p8Io6fw==
X-Received: by 2002:a05:6512:3e19:b0:592:f663:6bfb with SMTP id 2adb3069b0e04-592f6636c4emr2385576e87.56.1761345293360;
        Fri, 24 Oct 2025 15:34:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y13i0OqWMIqgGncQvwYhhm8ekADf8nKrqu/2CkOq/c+w=="
Received: by 2002:a05:651c:4388:10b0:376:34ae:d65e with SMTP id
 38308e7fff4ca-378d638590als3576901fa.0.-pod-prod-09-eu; Fri, 24 Oct 2025
 15:34:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwPbRIyotPYtgao6UwtF6ReEsHA6lmA9MRKfBomfbj6kWGmEjWDZlWygU1rcBe9B+aDXtYMPdO3Iw=@googlegroups.com
X-Received: by 2002:a05:651c:2119:b0:352:6aa4:3cee with SMTP id 38308e7fff4ca-37797911502mr92307931fa.17.1761345290131;
        Fri, 24 Oct 2025 15:34:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761345290; cv=none;
        d=google.com; s=arc-20240605;
        b=a3upqWv37vNrLc8Y0PIrtYCnJMPxk9Nm1xK4QH1XKR1eTe0YrfriGS7Wo3FclAykum
         3edzxUsHhBwDac9YJnjli7FlDmcccp424J7UavWJVuDHBxJC7rLCwoP+YNEyep8JXvje
         Nbr4YhoPylMkj4Iw0eeSkViGNrCXsEPDQkwdz2afnd4e626QPoKVm/f/Dc3GHqctOpcj
         I34+mdjQkQJxgTiC6vPlECaRvAYKCygzY9w1fUuYfObhmCIC2MsKWLtb8RHF9pmz/C8N
         YCOKJVSn9spQ+cYRrPurhb4vAfsLW7/JvazkysB+Fi9hKSV3smrPau+L/nM1EWy82Avy
         Q26g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dgWMmy8jJ+GexnEc4sqtdfOGQCxpNGU9Ux5BrjtS6oA=;
        fh=cFQNFhlFZfKXahxYwz3N8TSNhitzuawuz7dm77n0G6o=;
        b=U9G9URKAyT/hG8/maWjh5xteuHmPq0D9wKc4fdzXeyMKCWmt6W3AZSWkN+1RBiFbeF
         zr5QYVKiZgxJDMuas4VpLsFYbVm7O+hHha8p2ya9sqg6lwrfzlRNALqJAZCefZUEoYej
         pv7R5EvcvTkHuckJkihp4FjL7FO74YQYW4W1uVMm4m4wGk4GTfl4TfalvHOhV8dXtmPF
         0MlLXfK0JHl+9ujLOvEBLoWdY1EyQuhK28oVd7OGvxKeWvtrZYGo7VMoidoWTj1Egfmx
         oT0WJEH0p+JM3DvnW5CDe1oIESrMtyAIqydDwaiGPTfslk3zilZZv8vGKN74VlM1zS9Y
         AZcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Lc7yveoB;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eef28281si14081fa.5.2025.10.24.15.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Oct 2025 15:34:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-42966ce6dbdso1748310f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 24 Oct 2025 15:34:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+Lq7nJmFhFdmCdYQbhUxXIfBkK+hRZwpkchH8q567f1ehbACWGJs+hYBoyceyuqtUN121OnCQqYg=@googlegroups.com
X-Gm-Gg: ASbGncsXef62Yk9D2/brM0qvupkiO1lyTDo5eQqpd7TL6CUcmXtj7PeLrEE8KoImREt
	bjHK0OTbOuRbue0DmuZoZWSjOxSqm54X58Sc4mFw46hHGT95fK8G1ycIlJ2G5jWiLG8Bn2DUKdW
	KlmtH364zkYMS6g2aOvfzJZT/SAJWcUBaA612lqqxLBD70Uquyqw6cgRdA2G+T13wqFOyl0gX1h
	dN6K9mCQwdGyf7VJoEAz5GXIej2yq/2SGBbUpd4TAQuvmH/iBP+kJpZoi9m8mMug11BDmU+3Q4+
	o8Rhenon8GTjHkZDKjRfotZ0GJHP
X-Received: by 2002:a05:6000:40c7:b0:427:847:9d59 with SMTP id
 ffacd0b85a97d-42708479e00mr22413715f8f.45.1761345289151; Fri, 24 Oct 2025
 15:34:49 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz> <20251023-sheaves-for-all-v1-3-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-3-6ffa2c9941c0@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 24 Oct 2025 15:34:37 -0700
X-Gm-Features: AWmQ_bm73zAZG0hwU9rfMl02lZ4uq3I2SSq2VpZGEnfSrxZZCZEFxDP-C90Ympo
Message-ID: <CAADnVQKYkMVmjMrRhsg29fgYKQU8=bDJW3ghTHLbmFHJPmdNxA@mail.gmail.com>
Subject: Re: [PATCH RFC 03/19] slub: remove CONFIG_SLUB_TINY specific code paths
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
 header.i=@gmail.com header.s=20230601 header.b=Lc7yveoB;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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
> CONFIG_SLUB_TINY minimizes the SLUB's memory overhead in multiple ways,
> mainly by avoiding percpu caching of slabs and objects. It also reduces
> code size by replacing some code paths with simplified ones through
> ifdefs, but the benefits of that are smaller and would complicate the
> upcoming changes.
>
> Thus remove these code paths and associated ifdefs and simplify the code
> base.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h |   2 --
>  mm/slub.c | 107 +++-----------------------------------------------------=
------
>  2 files changed, 4 insertions(+), 105 deletions(-)

Looks like it is removing most of it.
Just remove the whole thing. Do people care about keeping SLUB_TINY?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKYkMVmjMrRhsg29fgYKQU8%3DbDJW3ghTHLbmFHJPmdNxA%40mail.gmail.com.
