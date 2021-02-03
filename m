Return-Path: <kasan-dev+bncBDQ27FVWWUFRBO5A5KAAMGQEV4B4X4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id D87EC30D959
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 12:59:56 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id z19sf16814342qtv.20
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 03:59:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612353596; cv=pass;
        d=google.com; s=arc-20160816;
        b=W+5N5lWhXAl67ESX0gnR9TUuMHkfcvzr94d5vAhAuJiWZtA7FxmzWmfiLYR56rSm1u
         OwzXfo9ExgWAgMhqWYuv86zgGgA8SA4LWTZbzFZ3H7tFo6jdgJWmikJvcPjzAZCEqy0t
         APsNI0A5X4SkM0AevO/gdBezjoIeUbM03UpwZFxha0CoKWzCsHoDbCEvrcixt8tty/Df
         oB9BWo6u9M37R81DczV45sgH7+6FPYjC20rMTosvHgSne6ix+ky9pySzTAagyJJO5y6H
         QW69hFj2h01C2KzJfhsNaaN8EGwvK8Z/Yw/TRB7kReK0xAhgC9ILoG0BycHy2ara1g9C
         VZCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Vp+Q7GHUsOgkb5Fxb4QZYRocWJDlxZNYu+EPdolYqf8=;
        b=gVdjyIlzyMAdoRHzDpyDZSlQFlp/cNH8rYi44hwb7j8Kb2qO8rQAzO70oAXkMMakDh
         35v2GidvCO0MPgukNF5kKOoiRvLBDt8SDyG7Bqng4p9O5cfIJabmyYfwEddELrLN3oBV
         fuuzcedP5vTf7aSSCdQ5soOh+LlWuHUgTUhRLsY4rR9iyIwG1Pw3o7t/NEjwqjZnWVeh
         Dw9rfSZlMVyU+TZZSsA7GUM3oypRArlia73nbM0WRZGM2fmeni5nQLtMBTO/tdmWSZ1w
         ZTodNDdrvxWPO6JwmYfHs3UM8Ue4NkVtZLNotk18wl4bJ8C73nWyoskL5HKaRE7Rt9OU
         qRnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=d2+USt6G;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vp+Q7GHUsOgkb5Fxb4QZYRocWJDlxZNYu+EPdolYqf8=;
        b=SsbfaZQjPoYHL1B9ByoibElDnn9BvrgSsXW31IVjn74yQRILZW+HXJ8MIJ3TRGqru7
         LybKjz4uE+3/WqSXjv7wWHdk2fgg9eS3DKC0n8y9SdECD6GY603yOGwgBOijZnhLhwa7
         6UXoPjMYfBAQEJUNZygDvzxAv+IkXFUvGldBSDkVUWbKwznu6VgRBYBb8h81ZqKudedF
         LHpFBrCBnoTZjaG3qPuseivgjrS/YCu6TGl4+jTVBeCBlhgbwibblP6SJVYOdQOIdlip
         mkcFyi/yZnEc+7Cfsh0i7kpmfQodZhSpQMxJ4L7WKyvUgywitInrfdVVt8OK7IYoOLax
         IXYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vp+Q7GHUsOgkb5Fxb4QZYRocWJDlxZNYu+EPdolYqf8=;
        b=pXFSsrlxM0XIC4xyI4k3OsfjspKmPDsduMSyNDwiAgo+AAKZ7/Xqt+p8E1Y8VtbzPh
         3IEv3X2SovPs4uEV805qj9nSQxF09MAwNy7jcCTRosZuD4LA5UptEtC9XfMIdltfx8H9
         RLD+3mJvEhs9md3AIyWVHbHPmIcsdHT3bxjBRz3qCWq1LV8yxOAlGfQRA1PPDsb1W/Cb
         EIiNtMRFeKfTt9UqfQofXao152aw1s1eyaciy10bxuutWKjJcKhGfBKKXH0nbCjnZv9P
         ZCxWOS+qidk945NtJYrbPUF8T130oUsWKlQGIedwVi9KeFK6v2Za1TCLvS5wkOPZ36g2
         a20g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BjEKQNf0Ll+M9T2i21hcsrUi9j8p8ljr+kAAmvNs4Qnq8QQWU
	6hR1Mp8arbJ8c8Y9O97VCpQ=
X-Google-Smtp-Source: ABdhPJy7mjNg5713bo8YCFQ0kKG9txGELrwcRDb9brzhCCHt8Hs6ZMz7cktdf4CNM9cTIeJ0+EqvsA==
X-Received: by 2002:ad4:54a7:: with SMTP id r7mr2458997qvy.47.1612353595989;
        Wed, 03 Feb 2021 03:59:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4816:: with SMTP id g22ls709098qtq.11.gmail; Wed, 03 Feb
 2021 03:59:55 -0800 (PST)
X-Received: by 2002:ac8:5a43:: with SMTP id o3mr2022271qta.222.1612353595555;
        Wed, 03 Feb 2021 03:59:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612353595; cv=none;
        d=google.com; s=arc-20160816;
        b=IoLoGFYlYzK0OFI0Kd1aYuauYGuVh4KYuOqg30/zqhMJ8oya4qvN3miYCHvbpuE/m2
         vHA5ZNXsevJLF3oW0vfYZvfVK8Bo/fPcYluBJWZNBw/C8iWPlX0T9KRptWazD2WeU604
         9ZMhztZ5+kQnmbL1DoMisLgnCT7SKW17zskVCN0F5yqMiPs6pRJOFsol25KLl7Ce5qsB
         2dIvKYu2lFndnNJgkRiSdzS5ffLikdU3AXbXwWptY4pqqpvLrjkABVmLlg5lPsv0OmA0
         sBy+xs6+0KWOjr0oOirBF1mWwvmIY923TanQvj9L3kWbIvfMjWnq7Qpm7QGunvq1wxuc
         bfKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=4uA7JS93JPw+++xZutM775VMPEwshLnvxHWwIlWPugU=;
        b=pfp7ZODuE5nYRUGhu2DZJmzRmABGhPLQrCccWgOYm21Uo9MtKtZ8IWvfSFi8xVmaQQ
         9WTUSb+L+IJRHhdE/wWs7kWjQBHd8fKAt0fykiP0/HBFDIkJ4GF1afcZzV3Z1RAgMYQ8
         wWaVwc1c1O+fwFGXO0okpYsrB2Eku2DEOmKs/7dhF8/7UhtZOqBh/qcp9Jiscdp9/C/N
         4dNoWGMjto4+HOWsImlDGakvtQ/tNHG2bU3MGyIasX87iT1vrPQDT2MaQFNZcyG7cafJ
         Vw5vlzlaTvwxMZipsaIq/BoukbL0kbCZ39Wx+uNf4ZFZPq3McLIgYAlNnKNZ4C1Qt4co
         4F4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=d2+USt6G;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id a26si116873qkl.1.2021.02.03.03.59.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 03:59:55 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id m6so16517631pfk.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 03:59:55 -0800 (PST)
X-Received: by 2002:a63:ca51:: with SMTP id o17mr3244885pgi.314.1612353594659;
        Wed, 03 Feb 2021 03:59:54 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-1c59-4eca-f876-fd51.static.ipv6.internode.on.net. [2001:44b8:1113:6700:1c59:4eca:f876:fd51])
        by smtp.gmail.com with ESMTPSA id h190sm2196512pfe.158.2021.02.03.03.59.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 03:59:54 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v10 0/6] KASAN for powerpc64 radix
Date: Wed,  3 Feb 2021 22:59:40 +1100
Message-Id: <20210203115946.663273-1-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=d2+USt6G;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::431 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

v10 rebases on top of next-20210125, fixing things up to work on top
of the latest changes, and fixing some review comments from
Christophe. I have tested host and guest with 64k pages for this spin.

It does not apply to powerpc/next, sorry: there are conflicting kasan
changes staged in next.

There is now only 1 failing KUnit test: kasan_global_oob - gcc puts
the ASAN init code in a section called '.init_array'. Powerpc64 module
loading code goes through and _renames_ any section beginning with
'.init' to begin with '_init' in order to avoid some complexities
around our 24-bit indirect jumps. This means it renames '.init_array'
to '_init_array', and the generic module loading code then fails to
recognise the section as a constructor and thus doesn't run it. This
hack dates back to 2003 and so I'm not going to try to unpick it in
this series. (I suspect this may have previously worked if the code
ended up in .ctors rather than .init_array but I don't keep my old
binaries around so I have no real way of checking.)

(The previously failing stack tests are now skipped due to more
accurate configuration settings.)

Details from v9: This is a significant reworking of the previous
versions. Instead of the previous approach which supported inline
instrumentation, this series provides only outline instrumentation.

To get around the problem of accessing the shadow region inside code we run
with translations off (in 'real mode'), we we restrict checking to when
translations are enabled. This is done via a new hook in the kasan core and
by excluding larger quantites of arch code from instrumentation. The upside
is that we no longer require that you be able to specify the amount of
physically contiguous memory on the system at compile time. Hopefully this
is a better trade-off. More details in patch 6.

kexec works. Both 64k and 4k pages work. Running as a KVM host works, but
nothing in arch/powerpc/kvm is instrumented. It's also potentially a bit
fragile - if any real mode code paths call out to instrumented code, things
will go boom.

Kind regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203115946.663273-1-dja%40axtens.net.
