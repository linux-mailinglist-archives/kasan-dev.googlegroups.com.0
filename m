Return-Path: <kasan-dev+bncBCF5XGNWYQBRBG6ERKZAMGQE3ZMJ7GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 691C48C4A06
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 01:28:29 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-43dd9951c89sf97881081cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 16:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715642908; cv=pass;
        d=google.com; s=arc-20160816;
        b=O65xCywZzs7n4Mz7tzuJN4jBBc57dkIBnIM4BOgpY1gim0RtkA7hsRyOfskuC4Sv9K
         ZhXIbeQurGGTzfYH4P2wiQ4v5XjleHYQa+fuFI1W7Yl0+ROlOZCTiVg5iH/zVCFC2tBY
         O6ISij+RUUAW39FCpzRTZcnZEyE7kmwGl3V9acLx1EHMrO6rjKPF4DkfPCnNC8STfYB6
         JWjX2UdGY6xgGVvIo2WpUz/gDITj3w6pNpp6SMsWhgoF5ya4ArdVsw6Pwp3mF73OEBKN
         flJESUUM6Mian14g2SWuxXH+eEn19VSlK2gudy4LaDt27I61soILUNeOHN4DuYxzMgu4
         bXCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=tL2oEOltasz1Eb2SOTOWjki1LjpJ+uCEj6y+6x+t9AY=;
        fh=fFl1pqnTOfGNZCcg8dwlk7czMppPuxvyXWVj1oVuyu8=;
        b=nhCk5LZFf7p57v4N+9R7OGBEWLCNcoOTmRdh4fJ5H4wCN90aLzu5spNMAUVBvxq5bf
         ivGs7FIyuQJKxjy5yXoNm3O/c5cqPJEaaqdN+2cg0JZwvGoMVCrVsQ0LWaNevtFxXdF1
         f0bHYOG7mh86LCHtNz6I7cbWKfPteKuxdp1/ZOpB2HgbCH9hMUW2AsBSZV1u1eJqiLqV
         k3ZTKUufZsBTVe18K1SJQxpCq6DlCv2RRNoO3O23hpfG2HJUgHFi4MAkitQENUVZriYu
         xsMPFWQCV42KLcoaOIPSwupDGggCqAB/y0DjRozpStEtoOhmxGP0A5/3jrfs1V3LRCox
         cgBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=aO7pfG8i;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715642908; x=1716247708; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tL2oEOltasz1Eb2SOTOWjki1LjpJ+uCEj6y+6x+t9AY=;
        b=INZ90bYnYKbOP1jvZGwK+GU6z3VM0HiEDGGtVU+DCULF8B0lmCHPPdbPQhKsW5G1AH
         UkvSVVhTEN0jFvqX+R+rpDxfEJjchMdateDkrlcRZT5mwEY2q+DlBAxSkvR5hAAAtywq
         kmnJV/NnNrxtM64pYBD9pwtcss2fF4BKqR8ZZkD/iPAzrY2g69oHZOnCkJePZNoa+v1V
         wXtA4ESoEhz3ammfZEfqfFwliVrTA/c/x9DONeEGcTYC8dy7lZjwcOx9qX92ZXUukmET
         rMwQpzFQVEp/hBS7s/OALZKWENo807pbp9wboKeIpSPZPc7rVQdVB3uSJpXF8gTPjoKU
         dITw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715642908; x=1716247708;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tL2oEOltasz1Eb2SOTOWjki1LjpJ+uCEj6y+6x+t9AY=;
        b=vxR28QeG9/oPtMzN2QwpC5U7ajr1fOgrFUSp/QUj2XIyDQoZAr4Fju/txv5QBCCBtH
         bRfHONJJUzk5im46WXsp+3ksloGBlPkLkFBMZlhTePVZd1KCK48J/k3uG+zEas9EDSxz
         7fLTVFp3Hj1f2eW2CHu6KIoJ0c25nTx8NpzJcZxR1jf9IxoAEp73URnVUZKJzQNRhE98
         Q5yGn3VwSfIgVlit465Hyn9viIQDBUm/QMAl83WU9H8de7CprgFfAXrPX/T1AbOdMEQ0
         I4G+baj8JieyHNGy+3rvPAtUpC4pVkJ5Df9YIOeVm7VGfG2ODq5b51hmyFe55wm0UlvZ
         iWhw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9Z0V7BPLZOuFGLeM8U9HM6LFM8l0qn50BlCqVOrOx4/9E8H1eDPnDfhPNdJNdU8H1QJzERLteeICU+Rafvr4VQGyMnddZ0Q==
X-Gm-Message-State: AOJu0Yw/nxtXg/pvawKTMyh9pNBHiNlu0/m9cwLf3hesCKPCuJe5US3i
	QLi9AGU899+3/LO45vS7lW7MfuVoGSCL+bZFQh1kKKnyh9sPpTpU
X-Google-Smtp-Source: AGHT+IH28P4P954P+bA31BhdFY0+rGehSU9vLOD8HAR15x+Wf0QLzfE6ZQpSA68OloURDGIh7xxJgw==
X-Received: by 2002:ac8:7e8f:0:b0:43b:173e:ce1b with SMTP id d75a77b69052e-43dec39d1edmr245142181cf.32.1715642908043;
        Mon, 13 May 2024 16:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2289:b0:43a:e248:12aa with SMTP id
 d75a77b69052e-43ded7076d9ls15574361cf.1.-pod-prod-00-us; Mon, 13 May 2024
 16:28:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXme2EkquUx+21jU21fbWwXDl2k4z9v9hCpdjO6bIjhLHb1CMQoOlrto1CmWHILs5VIWY1InI1rw/s4rog1zLvcpPo+efJ166e1kA==
X-Received: by 2002:ac8:7d86:0:b0:43a:3fce:32c2 with SMTP id d75a77b69052e-43debf55b93mr229298341cf.3.1715642907335;
        Mon, 13 May 2024 16:28:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715642907; cv=none;
        d=google.com; s=arc-20160816;
        b=DHzQvJ+97Y9A548coN3DBdSM/8H+lcCf+5ChShifr6KSbRqoAaP+hUo8ZAfMcgcgo8
         8/VdvkJ2kRXM+WXahIENE11VFaTSVV9gfQp0/FL+eoXM+Z6t6TIzfE72aXkC7Q3jzUck
         q6OYaBol8GzgsxbUx9I0dIcmkHUci9bDSFwjEHGXl0KPgsWSk3QqqHieXmF2KI1M+01Y
         7Pn7fkP8xswwdCUFGnqrGHWWEcq6+NDo5LCa0G85KCt0BCIFhoJlgZ7LDCNtowogHxuA
         LGjlMfQJQCtag50uUQq0Vrx29vfZn546HEiJz4AkjOJ+Rqk1qv7mgMf8z9dlsEWzO7wQ
         bSNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Alp79KUasntAH1xAOt+qh9t4wrzIhrRSX97PEjrZLDc=;
        fh=4/7Yce8tYkthUqLKPMPmjHyVnVNWEZmSyrSY8s3ZaBg=;
        b=lmoAl06SC0w1ZkNuAJOPnic0Pngtzs5wcJ+GVADCWhxiyAW7FwwVl/3YaaHwRrgfNC
         HLpXKNhto47eNlRfbij0BrTSvbbe8Sf2bIE3sSx1b6qf+jR+PNwukF0vfZAWdNAqbv+2
         7dk+eaTrgX05lB0+9PSa+A6HwbiBhWkqYaBBjFBX2A5WXTNMDRQybXB7MgsqAgMHjmn3
         0hf6K/aK3KdmpxUrHspfIpYpSdCqUZY1dXmw14VRlFh+lyA4O5ZxtCXcrk+p8dqX60iM
         hDnjMopfxuQYG3wB7dx74wJak3cREGhuwbJzapT5A6vyuoPQJymIm56/Z5KGiGlMQsCo
         D52g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=aO7pfG8i;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-43df5496cedsi6699801cf.2.2024.05.13.16.28.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 May 2024 16:28:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-61f2dc31be4so4117862a12.1
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 16:28:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVF6JnF1PXG2YVQ1KyFuOg8ZgWhkVTzotzK1zfKREvk/VHt4oU2IZhHcArF+lnjThBherMdFnO0h3jfpEfMglTEMeF19BZW3rX86w==
X-Received: by 2002:a17:90a:bf08:b0:2b2:7c65:f050 with SMTP id 98e67ed59e1d1-2b65effb9d4mr20481677a91.0.1715642906269;
        Mon, 13 May 2024 16:28:26 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2b62863cd9dsm10304270a91.12.2024.05.13.16.28.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 May 2024 16:28:25 -0700 (PDT)
Date: Mon, 13 May 2024 16:28:25 -0700
From: Kees Cook <keescook@chromium.org>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: linux-kbuild@vger.kernel.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Peter Oberparleiter <oberpar@linux.ibm.com>,
	Roberto Sassu <roberto.sassu@huaweicloud.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Subject: Re: [PATCH 0/3] kbuild: remove many tool coverage variables
Message-ID: <202405131626.D61F8228@keescook>
References: <20240506133544.2861555-1-masahiroy@kernel.org>
 <202405131136.73E766AA8@keescook>
 <CAK7LNARZuqxWyxn2peMCCt0gbsRdWjri=Pd9-HvpK7bcOB-9dA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAK7LNARZuqxWyxn2peMCCt0gbsRdWjri=Pd9-HvpK7bcOB-9dA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=aO7pfG8i;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, May 14, 2024 at 07:39:31AM +0900, Masahiro Yamada wrote:
> On Tue, May 14, 2024 at 3:48=E2=80=AFAM Kees Cook <keescook@chromium.org>=
 wrote:
> > I am worried about the use of "guess" and "most", though. :) Before, we
> > had some clear opt-out situations, and now it's more of a side-effect. =
I
> > think this is okay, but I'd really like to know more about your testing=
.
>=20
> - defconfig for arc, hexagon, loongarch, microblaze, sh, xtensa
> - allmodconfig for the other architectures
>=20
> (IIRC, allmodconfig failed for the first case, for reasons unrelated
> to this patch set, so I used defconfig instead.
> I do not remember what errors I observed)
>=20
> I checked the diff of .*.cmd files.

Ah-ha, perfect! Thanks. :)

> > Did you find any cases where you found that instrumentation was _remove=
d_
> > where not expected?
>=20
> See the commit log of 1/3.

Okay, thanks. I wasn't sure if that was the complete set or just part of
the "most" bit. :)

Thanks! I think this should all be fine. I'm not aware of anything
melting down yet from these changes being in -next, so:

Reviewed-by: Kees Cook <keescook@chromium.org>

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202405131626.D61F8228%40keescook.
