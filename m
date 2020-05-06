Return-Path: <kasan-dev+bncBC6OLHHDVUOBBXEBZH2QKGQEKDFB4GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id B02081C670F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 06:45:16 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id o25sf383116lfg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 21:45:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588740316; cv=pass;
        d=google.com; s=arc-20160816;
        b=W/kni/Mcok/jC/zQCG+WCKr6beBV87ZejRorbMXxTlKo7DymaLZjVGgs3EqDMQIAe5
         7qS6P4Us+IW8HVguWAYM01uJ1ZAyZOwxCFYS0ykNsYP6m3m6zIrzZNwGAk0An3Qh4fdi
         1ZyxSmaDJuaCulhkbl5O7QyQ6OEHGPMikw4/jpco1Lh1v+gwQPVwlGgdbCDSzN5Zh59d
         HDhbiJfdFe5GmtMcWZ9tZV9jgjEzzJtP6puKVZEUi1ki+ByrusfFtN4efFxkkMU9jp4A
         M6Go7uKsyBC746c4p4ZtuHS73Sv/MTM6fl16eqktjorji9quJohOCrYkKYypHJtuYvo9
         +yIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y0ArpA6fpZ40z6ChaEgt+rpeGcZvRkhlid+cZEkE1J0=;
        b=mg5q+8K0olYLGtZB3PReBmweYk0yEfkFSCErLcQEP4L0jm1tXTXK3a4+fy0E7iHK2L
         BQtwSNKGTkPSj82seNM6RaOI3o/lZ2xRk6cKSIDjtpTCdT1rAOXABy7dWAJmgoX05mQv
         RMDWhjPv2NjhNn4PNmVADx8Tr1BIj2Y3CXUx1azPtFP7QRXOmAd1HF1QNd264WuG4Xoc
         AhaXN+1fu9r8SQMdRckUFAbg75iz1Pmbbrz7sxWlhXRiAqqG42O+0XLjvcelAK4ljite
         45ZlZ1xOrQojaTaCE0eLPmbM19xmFLjBLqj1vyADWIAkkRUCmqeh+2zEdgcjbn/y/d+X
         Bi7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dNYljanB;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Y0ArpA6fpZ40z6ChaEgt+rpeGcZvRkhlid+cZEkE1J0=;
        b=NG0gvMkbHY6S/Nv+kn8O62nNuWT3Rpd39T2+06krKE92a45nqpJXVGAyLEiJ/dLx+D
         xJRlO+j8shvfdkI4+b2vHbrWILwm//neSqd3hIk7hXdhSttB6DXb6MNxZOJ/EGkD2ceh
         g+vAGFNsWDtgQSHAVtlWctWDOBEOZVFeohuwcnX0BRLZKBGe7ySu8Q85BvkE8mYfPLvl
         0S/l1V26YwmHRGpRjEJ+3yQrxi+++jqpIdgOFSNLI0CbWPLhe7NZNInDijLROjwQFGUi
         fY6YQYMzN9PTtipjQaFqrsbYa1+w/rbwJONtRYO69GzMYZXVTzXtHinuCSMNIkF/hkxa
         uDfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y0ArpA6fpZ40z6ChaEgt+rpeGcZvRkhlid+cZEkE1J0=;
        b=mzkmFhX7PATkC/cub9BPU0W9FSQetb+/M+mjpTMmEuG9wUT4TvgbkgrRg9OdRHJKAN
         Na74btDcgfA6AmD9BaH6TByMvgTgE8tlAaW/P3+Pm1AkiHE/XUYf9s+um85sR+6iiyoI
         uGFI98P7nrSP+o/3KJK4IDKVTHMFzgZebq6iuC8IvBA//ZpFgRJJ4pYI6eub67ZNd+5Q
         sn5+wf38KPCr5PcTFJdCDFhztvHqmaN91zx0D/z8lqj6UXe7TZEHuvRp1hZIaOpLQSCu
         dEhYSVzWu+qGwLGx0M5JR2JNaZnkR+/HuTaWdRVoUWwFi1sDVeGC7tgPIQ9NfWMcuvMl
         cABQ==
X-Gm-Message-State: AGi0PuZxA8W8YC5PBMvyTQCtUA1dRY5thlteumpiz0jIPPqbYyMNLMOo
	bsyvJTdAhiLQliED4dcYfSk=
X-Google-Smtp-Source: APiQypIyrZIQqxRn+QsprVl8SBBSdItLTU/0gjjkoYoojw7Xp7w20ZDH+gt0WntlNJ9coqmLiNtbHg==
X-Received: by 2002:a2e:b4e7:: with SMTP id s7mr3642124ljm.103.1588740316137;
        Tue, 05 May 2020 21:45:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ef06:: with SMTP id n6ls48849lfh.7.gmail; Tue, 05 May
 2020 21:45:15 -0700 (PDT)
X-Received: by 2002:a19:2282:: with SMTP id i124mr3713233lfi.98.1588740315425;
        Tue, 05 May 2020 21:45:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588740315; cv=none;
        d=google.com; s=arc-20160816;
        b=IGBW+uJIBM2xkT57LnKzbUIRiuaTAt5ey8YwS/K8PTHj9K6ncrxx/+EmfqOwO3cWN+
         T266i2zsSXrRV749Nr5EIzCHzuVYkf/Y8+IX3OCt7Cy9SGR7L/UIHq9EYt2e0pIFbiWs
         h74K4LbFPlVtH/JWB3eHI/buHK0qXfQ3rq4X+ar7o2CRL47wutwDUOjDd5M1S+IXFNzQ
         9sO9v+l26VyY6qZ5lEZBNNiUbZUO04ERu3j8hRwAzpV4w1BrRiD2I82OQJUR2Fd51Td/
         FsIeBbOF0eHdFNqAn/pcUkeukR33yGxMewFmSOBqty8MKac0pDgxZxyPIfmo7MfqHzvD
         R7CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Iqotp4Pzqr9RQqsgLMpXGPLAwQseruKWmRPMUXLKxY4=;
        b=YJs6Z8mjQkd8v2dyARuGXqevPKJ3zH5E3A0LtFZx49VfLUuDaFV/xKBEWlYn5jQ55A
         aK8bE02E0yPcgzeZ7r20GFaqW5/pCtqgmDE9fQjmEwcRmsK+bwhEb5bDxSiBEbNTJVaB
         keuuUjYdnbR4GD0BLfVul9Kz9cWaDCJI6MyJD6aB5QOkzmvmij83eoXcXDHH6pe/6rCh
         2+Og6GtsD27pPKt1YyeNWPVKEAIFWKE+GXLVDuUTM9Dkwins7jjMBP00HEJUTkEdFZLV
         uN9hnwWT9L28bpd5YoIDTapkzDt8RapXpcT0xSsmIMH1+2hvcq7SGiaxTDWIOSEU+9UV
         Mw6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dNYljanB;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id d19si49325lji.3.2020.05.05.21.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 21:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id u127so878188wmg.1
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 21:45:15 -0700 (PDT)
X-Received: by 2002:a1c:1fcf:: with SMTP id f198mr2157051wmf.16.1588740314500;
 Tue, 05 May 2020 21:45:14 -0700 (PDT)
MIME-Version: 1.0
References: <20200505182821.47708-1-elver@google.com>
In-Reply-To: <20200505182821.47708-1-elver@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 12:45:03 +0800
Message-ID: <CABVgOSmg8z1TpMh7NPy0M+9Gs2JT097-j_XGBRGhKk_3y2J-oA@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: Add test suite
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dNYljanB;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::344
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Wed, May 6, 2020 at 2:30 AM Marco Elver <elver@google.com> wrote:
>
> This adds KCSAN test focusing on behaviour of the integrated runtime.
> Tests various race scenarios, and verifies the reports generated to
> console. Makes use of KUnit for test organization, and the Torture
> framework for test thread control.
>
> Signed-off-by: Marco Elver <elver@google.com>

Thanks, this works much better on my setup: having an explicit error
for there not being enough CPUs is a lot better than hanging. It'd
still be nice to have these be "skipped" rather than "failed" at some
stage, but that's a nice-to-have for the future once we've implemented
such a thing in KUnit.

I'm still a little hesitant about non-deterministic tests in general =E2=80=
=94
even if they're only run when CONFIG_KCSAN is enabled, it's possible
that a future CI system could run under KCSAN and report false
breakages on unrelated patches. Given no such setup exists yet,
though, I think it's probably a problem for the future rather than a
blocker at the moment.

Regardless, I hit no unexpected issues in my testing, so,

Tested-by: David Gow <davidgow@google.com>

-- David

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CABVgOSmg8z1TpMh7NPy0M%2B9Gs2JT097-j_XGBRGhKk_3y2J-oA%40mail.gmai=
l.com.
