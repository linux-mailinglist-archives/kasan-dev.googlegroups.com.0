Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGGY6HAAMGQEUZFTPHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 52ED3AAF5B8
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 10:32:26 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-607f1847986sf698190eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 01:32:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746693144; cv=pass;
        d=google.com; s=arc-20240605;
        b=WiOmzgr1kGkOZv3V9TrO8XdvDYvK0wcOce24ZMkIKiqJqbqffSZSIQy2aqCxFsoLtQ
         v8Vt47IIJomlvYoIpWyvvcl/fcax7e1P34JBHHKlG9283y9ySanPhrpoK3krkS4qEPdi
         HlM/2JaPuVunpubmrXcB5aes9SnNIx7+APtU+D8PtgstKlv7kR5hrxmUWFT1640sHHam
         5sKKZKaRQUGDgKDbFJNUe3PgQ5ydqCtIPC35Yf1UBmG1M2kuSLs2Z5Cp1uH/X/gWSk1k
         19EF1rS35Dv4i7bPLK+i+9X+s6aoVDhszvs+lgjWZFPFp/3hX2Wq15Jib/25p1s/wNMl
         cJdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FZteYVkSLfJLzijrCi87wX2YcUu5GWRoCj5YW5x6gE4=;
        fh=sZfx06t55Y72XieJRhSu6qjLKKcm+BUs8TCcUkAWqhs=;
        b=cytYO6bPMksj+99qW9+XCOrdKYPGOh9AeQa0tgB1LDFZz4PeDBQ4AKVeiJsIy1wSK5
         2QFXEq7QKrvPrzAh6hzK7R1Tn3+Kx9mN1W9y0VD6wRozVXK3Sc3Qwux2+NommTNl+3Gl
         4xKC9AXDxdxm+qdL2JTqucmh8CIh43MkCEX/2p0a0v7doxt0p1Pf34fOspj3wOjXMHwU
         0+rB0XlLPYsu2vLGRD6NsM/hDZR3RNATTDsTfqaghIP2B/nvKg/nzn0lpzKpDuerHziO
         0WyqACyDz5Q304gqiNcoQyxdN2Y4z36rdScmUz0TCuuSPwdJ1IqWyFSw+zZ+MlFabx44
         j0JA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xW5c1Zbj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746693144; x=1747297944; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FZteYVkSLfJLzijrCi87wX2YcUu5GWRoCj5YW5x6gE4=;
        b=O8YG7HLF++yzvjhiQpKaeQzZFRsEfJgg3CxeeQmYtFVeZRQQ3KZ0S79Q5Y4F1e41Ib
         9DMNhHB30m/y1Anz9LXuPrBs6Bmx6AzU+TaUJdEGNNzVH3ZdljnOcZTDh/qB4rKU/H2n
         kgjEepqO2pQRtfMpLF/DhkVXPj6u9SWTO839cRV+aLXrRp9v2G4onN6eZUZirQx1lu/Y
         vLNArgmV6qWhHRciINjm3HTyWY6281ZjFB6i/2bSKucDCMiW/QR6/yDMe0k0gvL8DF3h
         bTZBXdwAkn1Hk9CD/ctMrXzukHrO47YRPEE5C4cw5fWlD+5hMSB3y74O/lIeHChLkXhF
         Aipw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746693144; x=1747297944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FZteYVkSLfJLzijrCi87wX2YcUu5GWRoCj5YW5x6gE4=;
        b=MF6z8O1hYtgFXFEuIaf2xBM7QvNPOf9fGHnmKj65pjfxuRoyt30ZYQNalsS9U5QS8j
         djD8W9Uu4uXaEyiCYYdhEaSUGuSPv5O2db2t+4uS8V/Pk5Ho4bpKZexENrE+PlQZ1eIG
         oKqtG6VhmEeWklEIX3W7qm87IebkE89tfGwDPBebytQivzZxYaVG/6rL7YRjlIFpLVpM
         6LaxfoYpa071VVII0Uxm0ri98fmWh7hpgqzFbL1N5m1Ca9PuRfzW61r2fLPLseRWqiO1
         LJwAtRjdrU50E2j8pkkyfmDAM2h0rPPQdH976FT+5Agy2CfeWSmwEGu7Ir0pfyjCFABG
         lD+w==
X-Forwarded-Encrypted: i=2; AJvYcCXI1ZI3zj9cDWpWmh9clmroOLZqcavxu3EPZkiwRFkc4czBr/r5nqdZoJ4cyPlyuxLgZqaydQ==@lfdr.de
X-Gm-Message-State: AOJu0YxBU2zErIw/tC66obQo1uzchisIf7lseKYjLPUdDg+8hjJrkagf
	D2xHyQJD6LQavllNLeLbmVI3EoKadkMsVtgRtaF7IZH86HBaCQci
X-Google-Smtp-Source: AGHT+IENquEBSFlq5tZipNpzQZgqYr2b9W9SY4rGexn2ym5DkrMPgG8twRUN2ylWK8kkYjLsopJ1nQ==
X-Received: by 2002:a05:6870:47aa:b0:2cc:4516:afc6 with SMTP id 586e51a60fabf-2db5c13303bmr4041037fac.36.1746693144423;
        Thu, 08 May 2025 01:32:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEUV0l1julpjxQGYH4b7dW2J/mMlpIlP8d1VONzHFI7GA==
Received: by 2002:a05:6870:c90c:b0:29f:f1cc:36ef with SMTP id
 586e51a60fabf-2db8057531els406914fac.2.-pod-prod-03-us; Thu, 08 May 2025
 01:32:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXKjd8eJiqafY0Sj6pgxCCDzTMkzYDHhZltZNmToJbKbIl/XQsJ4wPtCYgeKk8pAokGH3+SBHoBp9s=@googlegroups.com
X-Received: by 2002:a05:6830:3981:b0:72b:aa98:9af2 with SMTP id 46e09a7af769-73210b151e2mr4406136a34.25.1746693143567;
        Thu, 08 May 2025 01:32:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746693143; cv=none;
        d=google.com; s=arc-20240605;
        b=MRGFwWX5Vmk7OzVby11IZqrB34V6y9zvnZA8D1s30dHEXZZN72QfQ7p1Wkmz+I89zu
         jtBGUzOU8bDFRmWPpKpN/q8oVNn22jan1G+Mb+gk+Nx/sP/wde13hdsNaMZBJhNT0MEm
         lv6A10qirkLittup0knNHHUYqJtF9l7c6SkiZtUKtb50OJnTLrmiv86eOPonB9SuaBXg
         nR+o2vx6PgKkrHrqIaMF4JYE/8VMta12TRWTC5k0vkFIkiXD/5ORVZhKmBKd48zFf41K
         GzFzqKBpABpOyJim1jmFlfhCVTVIJGQCi+piv6v1pm0btqo1hghCAa9oYb0l97cnV8eT
         rKzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=N8mZbwrs/5/HrYcaufL1Ugn9aNRzeB+rYc/9Jk/Dr3s=;
        fh=RqjpnWNzAQ3bmhANYcVQmmXjXlNVarEYd6+8KuQOivY=;
        b=B5cp3fTci+fHX3GjOpIPMeTfK3DT/Ki5Cv6WyOy3cboLh+ix0Jms1gBeWUVvQCuHku
         RS1YkObpywkJWF+aHDwQn7mfZpokBpHlfkL63L/7b3FTJ9LDvMyYll9FZa52yCdmgm/f
         +rV3xReOAIz1RNZzi6x3D7rm9kkwCKEgdr2wF7nMJQfQLAmvv/hRbagRrQKcBxKSljLW
         Jcct0k9OSFStpOKH+VBB/LT/rqj73oLvZ3veEeOZjhBDZcsSMbVifzVFRPiKJmiM/Ld/
         Mz5DPLWkVFkfSBjOZMQQ4bZa3gMRhbJaHgNdgICWQVflUp56IkPv5pCh6BIXBR/5r6QH
         /SQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xW5c1Zbj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73210a95c32si160028a34.3.2025.05.08.01.32.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 May 2025 01:32:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id af79cd13be357-7c56a3def84so76172185a.0
        for <kasan-dev@googlegroups.com>; Thu, 08 May 2025 01:32:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVDG5gfh+izOs/EyIrx2RdboxZ+2K0gjJWHYoo5+tJi9Rt/LBmnZDvIzinv1Log937NIKc1acOiglM=@googlegroups.com
X-Gm-Gg: ASbGncv9KgBsfejoCErivjbtDtv4uJ/yQXvJTG4onQn5Hq/AI8joQn+liBhn4Y14wW+
	ko5tG/+gpgpDn6t11lGO36lZ1kAbEff6T4w6RMx8BblZ/79eA8tm6WVFocU8lzRuEcH6V8umXUc
	sevoLKbf74GkdKJ1VBLdMQs/JYGstWpxWUY242g+wzU/E5a3YjWrmI9R51vnmb6wA=
X-Received: by 2002:a05:6214:5086:b0:6d8:a8e1:b57b with SMTP id
 6a1803df08f44-6f542aad8c4mr120881656d6.36.1746693142679; Thu, 08 May 2025
 01:32:22 -0700 (PDT)
MIME-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com> <20250507160012.3311104-2-glider@google.com>
 <CANpmjNMUFmnVweY5zCkkszD39bhT3+eKk1-Qqc0LZTUdPN0x=Q@mail.gmail.com> <CAG_fn=VuaiTB11bJraxQjoVxp=0ML7Zoth1CYjczgUof3Rhqmw@mail.gmail.com>
In-Reply-To: <CAG_fn=VuaiTB11bJraxQjoVxp=0ML7Zoth1CYjczgUof3Rhqmw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 May 2025 10:31:45 +0200
X-Gm-Features: ATxdqUE7xSG_AG0WDgqD8g8zoZ_7fGDEsRbmK90FzbLlILhlobzg4Gki4bJ9d3g
Message-ID: <CAG_fn=VYg3sveZ8ofNJsx6-rS6p2PDNGWAKj18LpYRu02hV6-A@mail.gmail.com>
Subject: Re: [PATCH 2/5] kmsan: fix usage of kmsan_enter_runtime() in kmsan_vmap_pages_range_noflush()
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, bvanassche@acm.org, kent.overstreet@linux.dev, 
	iii@linux.ibm.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xW5c1Zbj;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, May 8, 2025 at 10:19=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:
>
> On Wed, May 7, 2025 at 6:09=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> >
> > On Wed, 7 May 2025 at 18:00, Alexander Potapenko <glider@google.com> wr=
ote:
> > >
> > > Only enter the runtime to call __vmap_pages_range_noflush(), so that =
error
> > > handling does not skip kmsan_leave_runtime().
> > >
> > > This bug was spotted by CONFIG_WARN_CAPABILITY_ANALYSIS=3Dy
> >
> > Might be worth pointing out this is not yet upstream:
> > https://lore.kernel.org/all/20250304092417.2873893-1-elver@google.com/
>
> Thanks! I'll update the description (here and in the other patch) and
> post v2 later today.

Since Andrew picked the changes up already, we've decided there's no
need for a respin :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVYg3sveZ8ofNJsx6-rS6p2PDNGWAKj18LpYRu02hV6-A%40mail.gmail.com.
