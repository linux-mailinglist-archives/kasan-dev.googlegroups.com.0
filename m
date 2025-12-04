Return-Path: <kasan-dev+bncBCT4VV5O2QKBBEUBY7EQMGQEZBPSPNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id B12DCCA4AF8
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 18:10:44 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-b763acb793fsf148777966b.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 09:10:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764868244; cv=pass;
        d=google.com; s=arc-20240605;
        b=LPDaZTghcmurA/dNW1s/FGYTXjqJTbO6O+EyUKw8ThGfjwxCPMy/y7anE2Vf9Kdozr
         LN4ZZzlp0WGbsur7bgVEGDOyNzNbKh58ZGC764szC1/X1a3K6nYBc+6HyqA/5PXEyJ4E
         LPoOXFcIqS+tujidKQAARUB5hqJ5efWEj1dy7YXwtF1/ye8fxLC9do719Einkj0be6Vo
         oQbFcOolwGPw3u3jkcbLDjBFPitMD7tozNek7pkDWcs/Ugm/WorSzQJywf7GF1SKqGD4
         kzUgxRddKpbP3voZLOhUaFXatfuau8uRtZGlgIZvyTP1YjHRHZPFJDxJVgCigCbKMZxJ
         isbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=tkY+lS559iNZAlwgxeQevCLSlKLqJFVb6wFVQBq+zxs=;
        fh=Hi1brtCqgjeco8VRqLeoVgbf2iT/Y8UVcJsoMPQ3k8E=;
        b=TnXH25+QeNAO1hHNRId6GW4e0b6IWpYjzbp+c6dCCuytK+aSe4ZM4KIV9tq3eSeUSC
         nSwp2MuyATj5SZ4ISRExRTI0o98+ZVJGu5fVViS7D8nsUr5MuoJM+XrJuttyDvgJFtlS
         19IDa/TWB7SDeelDN1lBeaiA6vLYjz9izzkvfFA6hOG8WjqnDYajdjJv7iyPhqvEElDT
         v16vHnhgU3+XD1jl++aWvFX8yKhCvfVXAUKKweQx+LgUwats+5fHxW1GhJ5afQFyF0my
         2uRHLIn6lfmRC5wQQwZ4hQSNWyelF0Vbi4wIp039OO5/RojkerY/LXO6sB4DpLZUS3te
         0gHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GKQoKgu1;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764868244; x=1765473044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tkY+lS559iNZAlwgxeQevCLSlKLqJFVb6wFVQBq+zxs=;
        b=Eb5EnfrcRFfSMmJdGRzvedFXQgVMaEqOhncKNcVS15J75pV8t6J1yCwwXXBdqlDp13
         DLPqYGw4ZW9T0+WgE+ATRxwX27hIACcuFvN56K7mD+hT5EnlB8g7WJYJWx7M4uK/oeLw
         lFDvn8295NHTUH36fKijcankOPLD1N5pjUUG7bajMAnSDV6QRJUUluOP2IgJB47t5knx
         Wo9ytLAgmwNbDk9no+vslkmD8G0/7JxMiOiOQauM393/XMBekvIUBZHKWwfWz7AlyAfH
         XQYZZNZgaZZrArvPaM0RxVL2E/DRR5KxvEuyKM6K69uftHHluRH7PAZE+vVY5EK0jBx+
         /V6A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764868244; x=1765473044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tkY+lS559iNZAlwgxeQevCLSlKLqJFVb6wFVQBq+zxs=;
        b=RyQZ69te5bXMiILXSXPRYVBMfAMmluA1YcRvOgPvs2y8d5z1fB6SX1ZRo3L/H2Jr5O
         Rie1/uCP8odUx4yXlb1yyhNATBraIIbT4/1esLLQqP6JvhIB5RA1zZdRDaQa6VqyYeG3
         +p1yLjSYgrMXEBnTKfDVpg7GgGBJsCOvRoRVNNG3gFlTaC+2O/5rl1J7BkapAtFLXQNa
         gCe62LDjKjn+U7kQxFomXnSYw/sMHp2DDwpXhXmklwpwAy2ufffI817qVgyKSvQFcNfY
         YFpf8YBPMj0r8fIdgZbfTVhQNM4SgKyI4Of1P2FjK43Re8dQJP/CRVM0/BQxEkOeVf2S
         rIIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764868244; x=1765473044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tkY+lS559iNZAlwgxeQevCLSlKLqJFVb6wFVQBq+zxs=;
        b=uuLR/M/sLictfY9sWToClI0FLMB1hZfJ9GZFPcbkhnvytdZpb+XM1kheFeEnn6GQPR
         cMVCXEZQ1QLdy8c38zENscS9qlKgFaS+CfjYEbHCy6rkZHejUQMASJQ0dgYSlLIW1Ksw
         10GTetCLq7OzLoODMRW9E3Bh/ffeEA3FgUUjziCbPXZBEXHHUZT6d+2rw+Pzb1Mx71Lj
         YsycW3qyGLGLQ97EmyL9uqV76YgWxQ8YiQfgutpmK+fNFEbu5YEGtHsrhRssnM4RxHwu
         d84oltzwk4fvlPe7/zCItGoNVeqMT+Xx0FLK98KRtGQAy7B5MWzmpN/QKEBNKtnwWvpr
         SLRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMnMpBe766Gc5vpnwl+0pv030ErvALMDdVU/i0iuwM2weOVLLSbYGEr7LR+4X9HqI+Nel2fA==@lfdr.de
X-Gm-Message-State: AOJu0YwhsdgLoLkCmkLUNd0ZCo1sGo2k6XdwVJUa8f7yYasufJOQ6Eox
	VQvDVD5KcpMsR7Rwi9/xMFX8XrFBQr2ua4JDg7x9GG/N0D8rgkgEVucV
X-Google-Smtp-Source: AGHT+IGKArJis1Bl4jrxLRO5THg0ZkE8DPQXRf4EEUXrsPfAoEBOnJjh0MU7yqTZ1MqLF9O2F65kcQ==
X-Received: by 2002:a17:907:7f17:b0:b72:6383:4c57 with SMTP id a640c23a62f3a-b79ec6eb02cmr449969466b.55.1764868243442;
        Thu, 04 Dec 2025 09:10:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zi6+zqxGNU/vq077tUDZLprlX6i5JPhZqabW1q3zfKeg=="
Received: by 2002:aa7:c64f:0:b0:644:f95b:b16f with SMTP id 4fb4d7f45d1cf-647ad2ee2aals1278031a12.0.-pod-prod-08-eu;
 Thu, 04 Dec 2025 09:10:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVS6u4Rd3nsPfPkOh7VOZpF2o0rAL9oFRMUGf+KxFODPBN2EtZbWYXiejBY0tLWNLZV5j+6+ZrObqM=@googlegroups.com
X-Received: by 2002:a05:6402:50ce:b0:647:9380:10a5 with SMTP id 4fb4d7f45d1cf-647abdeb90fmr3862375a12.28.1764868240086;
        Thu, 04 Dec 2025 09:10:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764868240; cv=none;
        d=google.com; s=arc-20240605;
        b=C9Lq+gk828kCSCI1WZGI3uH3tQtSCYxQyhxNu3FFPuLbFqZFuvb7UgFSOj8pxKNa7s
         z9FIfAXwAZq4sbTT0IZkFO6eN/FAj07knAv94OrCXDmVEjtHverg67b4cnnCMShyGuWM
         kG3OpaGxkY+8HVA+MXXHb9wDkj2NRIXsZ367ybXwEcMi/HGjQvYyRW8psoBE9tKDWuGk
         qKlv2PAbjqSJ8TK344Ipd/qSaTQf5j8631UX2wSsDZbWlQRKc1K25cBRBPrB1UPbgSuH
         CxUmIC+OmEK3nWAtnCJcY/ir2xT2VF871gthdWeR88eDJ7Bd8SHNBDz9CO3hlOcdMKlK
         4jJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Luu0dLPCGlCn7g8rOb8w3AI39PT79ZYzQ5Pim7OffGo=;
        fh=UbG3iTa4VEfk6MwnCKsD24xS5agT7D1Ncf4LuP5Zcd8=;
        b=MjRMshTnfMnNzOu5GvYtw0JPvU3LDS817xbv97ZLND/kFS6nmnnpDJvtXUGiG3kQfF
         iUycRLxE1yKTKxm4e/5tKvMxklVjutsMokItc9Sredld/znnEBp0kYtxfPi45cxJQQm5
         6t0CMlx0txj7Ied2uiPe+ztSQkx/FpCDU+G0ZOZTTquerI38oKdUshBYLX4vRhZRjarj
         xuzIJth91s0OIl4xTQTQ0lcNYoKkYsKWds3VKgiRvA6H0ylrqKu6WMNbVLE8rXMdNRX3
         b9wPMp83la8Qygre8+0Iz9X5pwz2Gedn71o2G4PJB7BFmgI5rhWUOn9cpKssivbtG9Xo
         Z1QA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GKQoKgu1;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b317f5b0si37681a12.7.2025.12.04.09.10.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 09:10:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id a640c23a62f3a-b735e278fa1so213266466b.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 09:10:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUexZlJ4YZG3aR5y+nWTxdS2LkwkZhqAVVqhIIC40KqGCDcbkE9jg3AzjlosddteEkM/hs06RNPLww=@googlegroups.com
X-Gm-Gg: ASbGncvez94mOBUI1X8PdC26LzHy0d4W+vNU+/FNU11QCfO6RdSHAanh0LcOKYL4M0N
	FvsSdUWh1aOHKVLrBvCkM4KzbFivJxnHm2+UaJ0oKaABuPjJEpRbRs339cWTGpulMo0h58ImDJd
	g/1nx16bcEHdsyEy5eWNvfzRCJlIrDHMhaZXMsqZrQbwOr76e8pLH2+2+gFNlwrvP9oU/yQkCcx
	5ptRrwjgpUsnzxbUzGyxSal1CmsadfBP7riDvbFrmkrUsGc7Nfq46CEfcC3BFYHijNHJW2Tyuzo
	XJBtFcK3Oy4ByBrJ/NzLOtbO+3WW/gYuZJOpJOTqc2JhkC/79FAdzJwdk+NiM1oRGbdLSuw=
X-Received: by 2002:a17:907:7f12:b0:b73:4aa5:35e5 with SMTP id
 a640c23a62f3a-b79ec3f09c1mr410215466b.7.1764868239255; Thu, 04 Dec 2025
 09:10:39 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com> <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
 <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com>
 <CAHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA@mail.gmail.com> <CANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP+6ew@mail.gmail.com>
In-Reply-To: <CANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP+6ew@mail.gmail.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Thu, 4 Dec 2025 19:10:03 +0200
X-Gm-Features: AWmQ_bmM6LnwCv_8DkzClBvkpIFbzUw_4DvWZVBU7sLi5C0dPTkjJPGuyU2cHmI
Message-ID: <CAHp75Vd9VOH2zHFmoU5rrQCRqJSBG2UDCfKgvOR6hwavDVqHeQ@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Marco Elver <elver@google.com>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, shuah@kernel.org, sj@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GKQoKgu1;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
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

On Thu, Dec 4, 2025 at 5:36=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
> On Thu, 4 Dec 2025 at 16:34, Andy Shevchenko <andy.shevchenko@gmail.com> =
wrote:
> > On Thu, Dec 4, 2025 at 5:33=E2=80=AFPM Marco Elver <elver@google.com> w=
rote:
> > > On Thu, 4 Dec 2025 at 16:26, Andy Shevchenko <andy.shevchenko@gmail.c=
om> wrote:

[..]

> > > > > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > > > > Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> > > >
> > > > I believe one of two SoBs is enough.
> > >
> > > Per my interpretation of
> > > https://docs.kernel.org/process/submitting-patches.html#developer-s-c=
ertificate-of-origin-1-1
> > > it's required where the affiliation/identity of the author has
> > > changed; it's as if another developer picked up the series and
> > > continues improving it.
> >
> > Since the original address does not exist, the Originally-by: or free
> > text in the commit message / cover letter should be enough.
>
> The original copyright still applies, and the SOB captures that.

The problem is that you put a non-existing person there. Make sure
emails are not bouncing and I will not object (however, I just saw
Greg's reply).

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHp75Vd9VOH2zHFmoU5rrQCRqJSBG2UDCfKgvOR6hwavDVqHeQ%40mail.gmail.com.
