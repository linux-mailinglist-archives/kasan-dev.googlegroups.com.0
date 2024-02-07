Return-Path: <kasan-dev+bncBDBZNDGJ54FBBTFGSCXAMGQESCSDDMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 4307884D699
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 00:33:34 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-42c4a11c8c5sf1613311cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 15:33:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707348813; cv=pass;
        d=google.com; s=arc-20160816;
        b=nHYgaZmLBGF0t3TUe6znNd2+b6jLZW+xnxOFK8hNQwxdb19FBKUzpoAyYIl1iCbcHm
         JbH3/6BbfnkRKi2IMUtRP+TvXAkNgLy4UZtHt8uB7PNvrxOqJ2Q5o09uDHFMjk0dfSKn
         sPrc5C6hfCqFEq9ZgagZCPm5OOKzXctMUiGFbfn8VEDa8bOaNza5ourX1Kx6GaiXyZRr
         JDT9H7+M/6ufMjez1PqVZKbzr1wxNuVSSSc2BPrhPlQtfJuwgBCgfOEqc82qkLIYxj+5
         LTrwz/51V75WX/uKgDDVSqY/Xp03xgzuLUvV1g2L2YP54xd0oZaAOrpdvjk4PtVm3vcK
         4HoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=deIViWziXK/oY9J/fyt+MkIuZojs/+xIIJvQ+2PV5Rw=;
        fh=l8rs5I4qiPsKgq2Pm7MPNI0tI/RugILWhPKEH4WZyKE=;
        b=jXyNZY0rt4IkDSj0LAvxDXvz5yY5+HrHptuFrgjZajcA4k3V6ePq69913Vqu2CKu2g
         fGyO3GZfYj1otrePF3BYOWKNXSXwmSQirIgLQSBIpNkrq6uII8C0woe0/Pw1C9wv7tG7
         KkC8XkcRRM6sW4aUQu/mCAHL7iuP2hhJgFhnZ/EA78OkU2dEeWZt8PbmH9w16ZkfQY38
         6/MF3R+5L5NwJkS7awCcasAEhOzQn4tbhW1FynCYGvlyqsc21py0lML7sZnxYtepyTmO
         KEeS9l9LwDtarNDOFXJtLAcQbwsyxYuBiAAjPGRwHdWwbVUsKiao7xbct/hsSNL9Z3q8
         NC8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FX1MbzFH;
       spf=pass (google.com: domain of kuba@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707348813; x=1707953613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=deIViWziXK/oY9J/fyt+MkIuZojs/+xIIJvQ+2PV5Rw=;
        b=fgihZCyvSj4BAFtQAG1cUg+0Uu2BSvPkzmMmypAyUAu2+8fR2JIkGW50fHz/Se4vVp
         tLDzjfR3XXHAPstivv/w/ctch9lVKZV87KvCc9I47jO69+xQLApCCV2JI0oEAyEm5VtY
         ZnjeI4Fx9FJJF8qLz6LRzZA5G2JkHAAyMaMffLOz2S6UY0zs0X+hu8a1mdFnaHJATyzU
         W21roPmGT7sXc5cBDg+lZTw2za3MNBS6OA2NXzPjLmnWt491Obm4LE3Gg7s/NZTyH8zv
         iqXk9CXYL7mh38gudIK4QRJSJFBJyVDk+O1cUymO5A9NLrxSRjKK/oflJhCZY15lenri
         FuIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707348813; x=1707953613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=deIViWziXK/oY9J/fyt+MkIuZojs/+xIIJvQ+2PV5Rw=;
        b=IMHPyn5VtR5lv1wlhQbnnoWSleJL67x6SWThBedW4yWxruxWWETNQskyWriL7aNyij
         cBEA2XhJaRwDflU9l5ZJv6rjFZpfCoZWZlc1kMYWDCQLMQkiWptpfep9ozXSvfBiUj48
         i5Quw/+9DhBTNahRAVHyNPeASBgiqSf79qDwtI2RXWfSgCTSJbn7CNTkp+fUxRyAmceP
         2lOJCdoU/Q4VZEMpNFb0PCVpolH5YeIAuOEg/PBW4Et/3tpgxyoymZPHEZESi9yOKJa0
         JZsD5wJb4N68lFM3Jta9MYmmxKE0rYiK6PrU2KunpvpwJqitLxfIGYrzTdeuwK1z7QlY
         yhPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/5ZhUc4NIMAdTtONX58V5reUkYXKKi7ashbi73jmx2FWpz3c6NZABxN37amCV+HoDYZOTP/swBnA75ijj7GLm9F8oIrVGAQ==
X-Gm-Message-State: AOJu0YzW+NINCZcKWF3R2qiCl8ObH3TbEd2y8CeZoIz+mZjHit2Xygcj
	692vwBMoMT+ItfFKxBV7clZR3up5eDPXYWko/uoJGZsHIen8rBcjhdg=
X-Google-Smtp-Source: AGHT+IFOkkTh/5M9uSnE+FQIumZVmJTqF4wr/t8acNB9mrKVIk2Yoc62JlLJK2wj5IoReeiR6LGr8w==
X-Received: by 2002:ac8:7197:0:b0:42c:10c3:9016 with SMTP id w23-20020ac87197000000b0042c10c39016mr6594948qto.65.1707348813126;
        Wed, 07 Feb 2024 15:33:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1356:b0:42b:f2bd:5401 with SMTP id
 w22-20020a05622a135600b0042bf2bd5401ls1711733qtk.0.-pod-prod-04-us; Wed, 07
 Feb 2024 15:33:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvXIe8a4eV2BvX6bDclUTIWu6fC/8/8T7RLN6oQsMCaiLnSes1JAk/0FIdfzMJ48oiYwAcmlCQ4nqPco2GUp70hMR+UV5xmPu5Cw==
X-Received: by 2002:a67:b401:0:b0:46d:2786:433d with SMTP id x1-20020a67b401000000b0046d2786433dmr4444373vsl.25.1707348811831;
        Wed, 07 Feb 2024 15:33:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707348811; cv=none;
        d=google.com; s=arc-20160816;
        b=W7CvMHnOMb5JOm+yWOJ3C4TlmjwYUttNsfoCMvtPGYER+DRq++55xGpjDRzFo0uafk
         zpQqXz+x0hvzocswG/aEvuffiAbanQinyI1LgNjXRnGio9AUj2rs6mjh8RsdMcjpon8A
         a0xAOUXUdcrpL/9GKPCZQS7nl0OHD8uURFkSAV2IwFYUJXWHFNQ4W0VMhJOzy4Kin/0b
         Q87BA78crA3/3u6k5qKKmv/mJVkHrMDyeUQB23aAdiDeb+vRUnrt2wnQhSUY3Ek8ilmf
         3sYpX0oT/94ezpILWlvTizfDaF/wx3RO4krYrOpXS/QpZrIkKmU+Or84+i/kzykk+Cvq
         r1gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=l9lRFT7IAY9RmLz2cfMu4MvS7tW3y4pnbckdNe8XMDo=;
        fh=D4IjROMukkya92fNGh8v4nQeRt3Ycn7f89Z9krXFnsQ=;
        b=rn7axsIO5L+G067rGXyRuHqz8h3g/MMWChf65c6ABUmnTfLyCxAMWV+0xQ0K6tsobZ
         y0UMLMM5LEQ/oictqNMeUfk3N6F5hzH9zP86ucOK4a9usWgAHq3hS7h+xUVmtRd4gMNB
         tEGvJKejLcXfc6v2Nj0FxmQ/HAti1PcT8F8uQVGGal4kS+hhsAdDVjnCWzfPwbte8BkR
         LjUfm4sGKiik++VaXgbLeAtovpyHnp6hcv9LKT6h+IUx1/5UYhBqoXf/f6x12LCRcMyO
         XTLBt3ziRWW0ii/1iZFDKLOTObttc5rg5adieHo3rC8A2TRyQigVEmiA3pg1mIK3cbwP
         FbgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FX1MbzFH;
       spf=pass (google.com: domain of kuba@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCXKqetB9pzc6o56iVe7cVnnmykceZTjrj6tj8L24+dDmbNjP5gTShpOmLms7OYtNcI/t9GyzAUbroXJz0I27aTuK2UkNYuSZV1ZJw==
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id fq10-20020a056214258a00b0068c907ba310si415313qvb.8.2024.02.07.15.33.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 15:33:31 -0800 (PST)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 2D781CE17D8;
	Wed,  7 Feb 2024 23:33:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 18E1EC433F1;
	Wed,  7 Feb 2024 23:33:28 +0000 (UTC)
Date: Wed, 7 Feb 2024 15:33:27 -0800
From: Jakub Kicinski <kuba@kernel.org>
To: Borislav Petkov <bp@alien8.de>
Cc: Matthieu Baerts <matttbe@kernel.org>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, kasan-dev@googlegroups.com, Netdev
 <netdev@vger.kernel.org>, linux-hardening@vger.kernel.org, Kees Cook
 <keescook@chromium.org>, the arch/x86 maintainers <x86@kernel.org>
Subject: Re: KFENCE: included in x86 defconfig?
Message-ID: <20240207153327.22b5c848@kernel.org>
In-Reply-To: <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
	<CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
	<20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
	<d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
	<20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FX1MbzFH;       spf=pass
 (google.com: domain of kuba@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, 7 Feb 2024 20:04:44 +0100 Borislav Petkov wrote:
> On Wed, Feb 07, 2024 at 07:35:53PM +0100, Matthieu Baerts wrote:
> > Sorry, I'm sure I understand your suggestion: do you mean not including
> > KFENCE in hardening.config either, but in another one?
> > 
> > For the networking tests, we are already merging .config files, e.g. the
> > debug.config one. We are not pushing to have KFENCE in x86 defconfig, it
> > can be elsewhere, and we don't mind merging other .config files if they
> > are maintained.  
> 
> Well, depends on where should KFENCE be enabled? Do you want people to
> run their tests with it too, or only the networking tests? If so, then
> hardening.config probably makes sense. 
> 
> Judging by what Documentation/dev-tools/kfence.rst says:
> 
> "KFENCE is designed to be enabled in production kernels, and has near zero
> performance overhead."
> 
> this reads like it should be enabled *everywhere* - not only in some
> hardening config.

Right, a lot of distros enable it and so do hyperscalers (Fedora, Meta
and Google at least, AFAIK). Linus is pretty clear on the policy that
"feature" type Kconfig options should default to disabled. But for
something like KFENCE we were wondering what the cut-over point is
for making it enabled by default.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240207153327.22b5c848%40kernel.org.
