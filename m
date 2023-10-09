Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY46R6UQMGQEP5NEBYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 27BC27BD7CD
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 12:01:09 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3516575f07csf4312895ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 03:01:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696845668; cv=pass;
        d=google.com; s=arc-20160816;
        b=b5HD32qzyAXr4O7Pi1UWFrL7LZFDlnN4+xrqWo1YOHq+4ZC4wPDMwE553nzFDo0wpB
         TJRBdKZ3okomhQZ/jH+vhcW6WbEK/qcbl4DryE3b1iJIGgnf27ZXeMYdGGzx97pkQFvV
         zxQ1a1spqBrmpSogCfzx4ffCbNRir8thIZXBHAkAItPkgqPmDQUku0M781e97TQNOXoQ
         nE/GMdmB3XVMMCrVekmBDvLCiOfFpY+LBTIQA0G6dr+ttgEpCEjTdnedwAMX13ycy+EL
         5Zake1yXrgLguN74FD2Va7FjY8ZNx18JSOQwLUPqpvoS5LD4nXZProBtCjEIZrysUn3Y
         X5ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HRVxlhmyuy7gYC+fpI504UCtbge0DYFaDIcc1mYHpo4=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=GIGJhpzNyMInw9xVM8FIHjoBynBRslNxVEw2RRsyZi31CM2t2tf0Tp+BiG3OAQBnBZ
         /mivDN0VgnIPbS4auZWWSgVjW4E21wEJpK64yG1dlLZg3zUdbct+e5NoneeIrpoGynp8
         vWePTzm/ClFWa0jFop3BzUdgh6+B8Snv2Oe3lfFz7COxLZXXUVZQLovVgqfhR8a8LoS+
         rLDR6yffUCZA1VGyGssv9ywBrYJTYT6YPLCpAx9tG/OSGkzUr616rUABb+sLKiWTqfiQ
         pXH1XUiHOAhGQ3tIXBmt+pasFje2TsCAh5vPEpoClSH0ZwwvGNo4bezU1yq7lrLxdjP+
         vuJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bs4MNuTH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696845668; x=1697450468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HRVxlhmyuy7gYC+fpI504UCtbge0DYFaDIcc1mYHpo4=;
        b=vMukbNa0HqsPH7F8Xb+CL5tLwZIxJWshv3tqmcOazGT3cHH+jeW4qkR+iNE/V5hZkV
         ePCal8euUWebCosr7MFDaehDUxaWy8p0a5QENixtJ9eAe8+Gfszh1+HV9cTaCUvC0gFE
         G2ZZ4dpYwGy6KbABe+bwHQ8qD/a5oAATNgLctDWHC3zHUhBZGd1OddC14UpH6290WZC8
         W71i2ELoNvGGgGV4SPdgXQnOTukUQnbxc4+XyBFOkfRi8W6AciT4lw/f1YmiU+QAVSOw
         b9Ycy50HtH8OAHH+XNm6UpJUMUfCh2N4E3nJymS7qKCuBHZihRti5tc0lFs1YMLDBPpF
         F4dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696845668; x=1697450468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HRVxlhmyuy7gYC+fpI504UCtbge0DYFaDIcc1mYHpo4=;
        b=UjSYbDlvLEnvS/5RHMyu4Tk8QK9h9FIQZqr5Kl1I0v8tgL1nOYZ3ArQjpPwyqF7Ndp
         w/oYhlM/G5gwtoyNchknCl3aXcbI0pSvZbC56aW5rJYTzAQCGPmuYGzF4szIIxhCEcmK
         +9mdfB2pQbaXhfxK0l2lrH+sB/1aR2wsMUR6GGd3kY/oVHYFwp2AAQjwRd6GjkgUpEMV
         J3BTKXWjQVDwXqvbzrK2VQOF2qRq82CF+TD45k+l+y1iaPCtLcGyera5jRPEFHKIYjSa
         ZU/OfvJNwrDhggJER9lMhYwBV8JG4fUx+4SUyY4J4tlsGZloPW6GMav1EJCjUpUxvNjk
         T7Aw==
X-Gm-Message-State: AOJu0YwplVDjEtDY+xqM0nPgZ1wEBe4BF8IDCtQn1wclBz0lqgaqJy01
	QmDnMbvMM4lIQwzqNJJp1W8=
X-Google-Smtp-Source: AGHT+IGrzb5sBnecQZTKtPwe3jy96EnoLqkZjH4dgEJyJwCEH4eyvSbcjhVqZdz9DaeeetzykZmOVQ==
X-Received: by 2002:a92:c246:0:b0:33a:e716:a76a with SMTP id k6-20020a92c246000000b0033ae716a76amr909569ilo.24.1696845668001;
        Mon, 09 Oct 2023 03:01:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5101:0:b0:57b:7aef:9d1b with SMTP id s1-20020a4a5101000000b0057b7aef9d1bls1451419ooa.0.-pod-prod-07-us;
 Mon, 09 Oct 2023 03:01:07 -0700 (PDT)
X-Received: by 2002:a9d:784c:0:b0:6c6:1c54:a1b7 with SMTP id c12-20020a9d784c000000b006c61c54a1b7mr16721241otm.24.1696845667388;
        Mon, 09 Oct 2023 03:01:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696845667; cv=none;
        d=google.com; s=arc-20160816;
        b=bZOXvbjlL1fgFP7OELE7OD4m4JZOA0yeqYPZPrC6DTN4bmI7cu1UXli8UcyGDvUdfw
         /+fYb6/3ZOhu2Abn7z7jYOF5mXAH7rNVMkSnaDe1azEoMDOzvAVPTWyfGSsDF7o3HBpH
         A4+QZFkBnFQYDqLLSEBW8fTix7918P3t73zU07yHDizIwBDoGxlXf1GlECVpfnyVfQz/
         bSEvFweDKa9OG/OcXAIkbaJsJnp52wFEkc78HTyfDqe8l3vri0M7WUBnqHCpwevhiGoc
         VM3t5W1LiQ2VujyT7PGeYFVV/VzR4MSuVDSdTa1nH3K135xjMIdzI6Hv7T+/k8rSImLN
         ueBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HotZPzuJzl1SmzAQEp1ojEnv3yLnH0/BdTX3c1wN21g=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=GVIEYtr6+ogFbbWY/tPdpr4oxDdGlbXfNMsbd/+zAw3xaJ3XUM0BSma1li3OMWgc1D
         ZpQYyC3pjHQLN7xI/OKrUkLZRmasb3k/sDzJmUvbRUXdL+6w43cS10LBlKrh7HpmIqcK
         mS8hWyCGqrXEUjLp3rw0w49BqkHvP5/xjwx/cAgV2S0z3bwxuYyWIsNQH1YI4COfLyv8
         2IJpoXNsVh+Qaste0PowYw+xvKzIFvBRGAIuMPzYE9kp0ucJkXv5uVY82O631cQhK7/g
         2YLP1qEg6d6vfg4aw6E5zpC5mxa/3C4TSQonNy1O5Azu3NB+DUwM/UoAQgUyR3zr20yH
         /Oyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bs4MNuTH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id w10-20020a63d74a000000b00573f7777b2esi660817pgi.2.2023.10.09.03.01.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 03:01:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-66ce3af282bso2380076d6.2
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 03:01:07 -0700 (PDT)
X-Received: by 2002:a0c:9cc6:0:b0:65d:b9b:f327 with SMTP id
 j6-20020a0c9cc6000000b0065d0b9bf327mr12581237qvf.63.1696845666421; Mon, 09
 Oct 2023 03:01:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <7f6b58fda637238ffc0c240e7fd3b3a6673d9d91.1694625260.git.andreyknvl@google.com>
In-Reply-To: <7f6b58fda637238ffc0c240e7fd3b3a6673d9d91.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 12:00:26 +0200
Message-ID: <CAG_fn=UGeH_eWcGNjX2uZBaWtVcS5pkikOx0+4UYcCqRLjHceg@mail.gmail.com>
Subject: Re: [PATCH v2 13/19] kmsan: use stack_depot_save instead of __stack_depot_save
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=bs4MNuTH;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Sep 13, 2023 at 7:17=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Make KMSAN use stack_depot_save instead of __stack_depot_save,
> as it always passes true to __stack_depot_save as the last argument.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUGeH_eWcGNjX2uZBaWtVcS5pkikOx0%2B4UYcCqRLjHceg%40mail.gm=
ail.com.
