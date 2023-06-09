Return-Path: <kasan-dev+bncBCR5PSMFZYORBX6CRSSAMGQETWFGKDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AC1A729AC7
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Jun 2023 14:56:01 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-662f0feaf61sf937976b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jun 2023 05:56:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686315360; cv=pass;
        d=google.com; s=arc-20160816;
        b=AiNpCej3Eo18sqvb4+nZlS4EWLBTNE5um2tdReCEObCPjoZJQj7nF1NanJLHZzMEYW
         +RdzIjhO2f0+Cuw9IrdR9fWPv+lHCsIE5exL31TgjGDcIuNawku8xYafSjKQaZw2H+TJ
         v0WKjYEunheU5R2LezvZ7z4n/6eRZg4JDAlU1v9DnqfNovwmsTrToJocGDmAdruILLSo
         8IlIk0aEx9SJRJxczAx4UnKvdSFOxm30Ib8C+9JUGMaBvN/tJ/Jn/xQ/u3xdc9HH090z
         6QAKzeDFe2EeS+1R8HPL9QuribWUce83TDTNTjvtELVGxsAfXW87Evuh4JxWT3EYJ78E
         bNsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=BXPaB0jeDdJA4vVWMMm8tK3AzWc/UMnsKGIzbgdyCjg=;
        b=rcpXdzN0N1iImvEOQAIw3Ga3dxsS6KNWh4dLXhkEdIxIj3XY8vs0Ub0CqPI00rjtz4
         dgmgEp0fvQxG6OpB0ixNHtT6E/rmaYGTMhucgD4P0KV3AZzS3FnWkuCks8yQVpZWXP9x
         q4QWRUee66Tzj25KfNp9EdrcC9+DASGDILEabUFcJ4N13Ihqnx0F4QZmOg6jpFlfQkza
         C3jXleKYDeH5hcuqk/5j5t7PO8cfmp+zwhXsPnukPPdgLPh4ovoRfgiGAxxKhCROgZej
         otlABAz5VriOy+7O8crY+4wQM1lrk0FPgbaE8CkF39n+8gvUO9fYxGOPhSAkuQ6OgJx0
         ToMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="EwB3F//8";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686315360; x=1688907360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BXPaB0jeDdJA4vVWMMm8tK3AzWc/UMnsKGIzbgdyCjg=;
        b=Azk+kIDF+Xz1qoR0gPJRkywRQ/6nRfRC2WfNTZg2NEa6rKjWKsC+63xQvo5qHNckzj
         26Swm5g7NVWVU9Lf6RGKij+R4uSbp0u2P9pf9xtivmeCzdt0uxtNO6tx1A//b6oUigWx
         oyi/JYqZhW9FAb78FO/DcxxZ55zE6xxLJpQRZYkXUd+Fo5T33xMAQTVeGmsfcj24KTIm
         WHvocJM2DDQNrJ963XvbxXDANtMM32DYEPF015ygNGyLSDsijKo4x1NL34YQbE7tpdsH
         +kDrU9KFgRFPGJPDS+a1zdRzDGpAToSGZde3uUtcyMc4MLH2jn5qQzwcq/qrW8ro/Vda
         jg2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686315360; x=1688907360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BXPaB0jeDdJA4vVWMMm8tK3AzWc/UMnsKGIzbgdyCjg=;
        b=UHqglLL02qFKCvyptjyWTEi7MZe2A8vYI6sQSZqZ5lquikhrFqWgDxArVyrHUIzueq
         mCld0IL7teiDEIG+ZNj+P7X/MMK6bEkewBao0tSs6Br7lpxt79VU/wwiYj5XEmhsmO7+
         6JeBFUuTDfvr3jCXhM/SbOiPkzP0F9KNqPZt4hNK2QWFy73SJqaYo/+HsW19l+UFNT97
         BbD/1+EGyaKZEBCYbGRGupblADrAvAf56D/oWcAHF2gXbv3MXPooVA90DxLdQ4lc1xHI
         ex4o5MFYciqu6EF1MAF5C+xeujSp9UzlpdgYwFDy71HCkjma3NEh+IGrURPy+wDXJUZe
         3g6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy/NS8qIWDFKwilTd37j2fYeGbzB/6gB4KZ8LFXJCCxrDa+GRZk
	s2SLqny9kxmlBuckAc7vj/8=
X-Google-Smtp-Source: ACHHUZ59/XUi4/ZvptYHfMEQPN5O13oC+i1RKQ5fQ1QbS9lbaDuVNNbPmrZMEj1mmEzv6cy5exaVXg==
X-Received: by 2002:a05:6a00:2396:b0:653:a56:10d8 with SMTP id f22-20020a056a00239600b006530a5610d8mr991375pfc.33.1686315359717;
        Fri, 09 Jun 2023 05:55:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:86cf:0:b0:653:8a1d:b391 with SMTP id x198-20020a6286cf000000b006538a1db391ls1339637pfd.0.-pod-prod-02-us;
 Fri, 09 Jun 2023 05:55:58 -0700 (PDT)
X-Received: by 2002:a05:6a20:258f:b0:10a:c09c:bd with SMTP id k15-20020a056a20258f00b0010ac09c00bdmr845796pzd.55.1686315358531;
        Fri, 09 Jun 2023 05:55:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686315358; cv=none;
        d=google.com; s=arc-20160816;
        b=FLgB1XsLTM+vpcvds+tjTMV/J1ayfla9b3jdIrq3YnhRZXqV6aeVS6cQ7UpzphVjBe
         U9isEAqKLdWyeOdS71ZYqWE7n81UaOM+iCE745DWKnPSki7f/8GcMHSd2MXgcsk5fHOm
         ZG28BY52uhToqoqkgLGjq79R9CQDpWiGwCp/0bpB+1FbYuuQnLo4fRr3Vf59GL8hTOWh
         dJQGM85+taBNmriTCNoKGjAXaZSNSPB13zrXiB7pvwLG50tCbpA85ZN07wuGJNgZRjol
         GdGHcdyFKemS/R2H2H1KfS1RUwzqnlFiqTU6I+VGnYMvHoF4cpnke7c3JcCnD8aKhr0a
         vAAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=6hU42edEeCSuu+D9dpO9GvNrSsgyCJqWaGuZfm40wB0=;
        b=TgauVhbF/QXVRVzIeqpsw66VuGraMQd3y1tCfVBZlKPAaAHeEoyR+A7Om6QsGkhYbn
         15bGVs74pfDcjjw3asADe1+V9hArsqR3QLMX8tIoKDzlEkzKE5N73zK4blwUYUZCa7rz
         7vYtEfKxj9rJx3RmggIk60zl7B5DQTx1bQsZykzlpX6K4uI7IRbnfAi47OIe9ijhHFj+
         lx/wcK2NdMfTsyg8yzNgkXEZBp8C/aXuQMncZM9A0Uto2b+S2V/Im0XxOYBsv67UPWkk
         F6TQvDtLyp9Gidifpj1HB+/szK2gk/uW8IKIPcYsldUIl2m6ZyVIkb9QJWY7m92qg5ZS
         eG4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="EwB3F//8";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (mail.ozlabs.org. [2404:9400:2221:ea00::3])
        by gmr-mx.google.com with ESMTPS id p8-20020a056a000a0800b0066115badfa4si381491pfh.4.2023.06.09.05.55.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jun 2023 05:55:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) client-ip=2404:9400:2221:ea00::3;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4Qd1KQ2t5Qz4x3x;
	Fri,  9 Jun 2023 22:55:54 +1000 (AEST)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, Marco Elver
 <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney"
 <paulmck@kernel.org>, Nicholas Piggin <npiggin@gmail.com>, Chris Zankel
 <chris@zankel.net>, Max Filippov <jcmvbkbc@gmail.com>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Rohan McLure
 <rmclure@linux.ibm.com>
Subject: Re: [PATCH 1/3] kcsan: Don't expect 64 bits atomic builtins from 32
 bits architectures
In-Reply-To: <662d074e-58cf-3bde-f454-e58d04803f34@csgroup.eu>
References: <cover.1683892665.git.christophe.leroy@csgroup.eu>
 <d9c6afc28d0855240171a4e0ad9ffcdb9d07fceb.1683892665.git.christophe.leroy@csgroup.eu>
 <CANpmjNMm-2Tdhp6rDzA7CYvotmmGmLUnZnA_35yLUvxHB=7s0g@mail.gmail.com>
 <662d074e-58cf-3bde-f454-e58d04803f34@csgroup.eu>
Date: Fri, 09 Jun 2023 22:55:49 +1000
Message-ID: <877cschk16.fsf@mail.lhotse>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b="EwB3F//8";       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3
 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:
> Le 12/05/2023 =C3=A0 18:09, Marco Elver a =C3=A9crit=C2=A0:
>> On Fri, 12 May 2023 at 17:31, Christophe Leroy
>> <christophe.leroy@csgroup.eu> wrote:
>>>
>>> Activating KCSAN on a 32 bits architecture leads to the following
>>> link-time failure:
>>>
>>>      LD      .tmp_vmlinux.kallsyms1
>>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic6=
4_load':
>>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_load_8'
>>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic6=
4_store':
>>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_store_8'
...
>>>
>>> 32 bits architectures don't have 64 bits atomic builtins. Only
>>> include DEFINE_TSAN_ATOMIC_OPS(64) on 64 bits architectures.
>>>
>>> Fixes: 0f8ad5f2e934 ("kcsan: Add support for atomic builtins")
>>> Suggested-by: Marco Elver <elver@google.com>
>>> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
>>=20
>> Reviewed-by: Marco Elver <elver@google.com>
>>=20
>> Do you have your own tree to take this through with the other patches?
>
> I don't have my own tree but I guess that it can be taken by Michael for=
=20
> 6.5 via powerpc tree with acks from you and Max.
>
> Michael is that ok for you ?

Yeah I can take it.

cheers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/877cschk16.fsf%40mail.lhotse.
