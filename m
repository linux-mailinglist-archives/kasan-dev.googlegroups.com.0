Return-Path: <kasan-dev+bncBDW2JDUY5AORBZPB7WPQMGQE253YM4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A1526A6FD8
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 16:36:07 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-536bbaa701asf280447917b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 07:36:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677684965; cv=pass;
        d=google.com; s=arc-20160816;
        b=r9fV8c0WjLyUh1Dn3EpD6VdftnVgr+MTxOEt40XuQ7FYqj/5A0SwpJrRqhWVPO4mYl
         7l2b46ILLbYyiuJCKScDwe2RGqCUhJnPt9apRqvjpRHIQeKLE0sui7379d3U3IIrh/tA
         kKqd3JLAC9AnTVYgzuls/CN5fN9NsLQagvFB30qZI5pTt7AaAcLqh5DKNkH39NUGTEH4
         fiUJgq17nex3df2NROsc5MEmNWfvreBe0lWEtHyLWcjlf/CaemWFEa7rGM+FrcqHimbT
         hUuiMCr3oZDkFFuEZYBGA2QiMOOgv/oENiqm4UqC4T+NQkRCdVWOeWUoIdi6d371Vz7c
         oV1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KXCqIMPP0sJrqoBwsh3984kwX7uFxi3cpCqTpMua2F8=;
        b=nhxW6c3m23UvjOqab3iMzbcd3USo+1I9p5KQ6KfrThHA6VNIKVwPJXo+SXq6wYVVyq
         dDWmTw8IwyxI2TYVuIA/y1V/A7x2y7JyfVHAzAQvBzXHk9SgGowGBIyy9RVXQXq/7BBZ
         Ud5m002FthTmo1nywHKZ4PLocQWupldPHFcknhgHQ461Ad2OhqxKRug6wdsVdy4976R4
         haK2l0k81y6BPK5omk2bc6Vrm39LTaACVj3Da2ml9ktQz4UgMJQ+2pgoijY7VcW9sCPU
         5HaXCzyxbNzQDSzGuh1YsiM7Qj+KjBvjZGrVP5JtWnA5EC+kkaVPdQkuwFMJXPkh3PUo
         ZTNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pF5MsrHt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KXCqIMPP0sJrqoBwsh3984kwX7uFxi3cpCqTpMua2F8=;
        b=LnSk2juBOg5O/gfKj3z0B6GXYnPQ+oDVcUvttGM7hDYxFNuiwl8XylsBn2bhyX7sbx
         mFlBB5YeWKH46t2QafwfhTIYd30bbu7UGsNwDSeotqnOcaRyAT1yRg5VK7pWX6sa22Fg
         fCknwhJJAB6PftSmtkyu16tyu+gn+9Mm9olVFHiprtEjqvTb2DQd0aUN30FNQZ9zCpfL
         8ZbUbd+K84h45QqRZxZyoKTONMsPDm1yjtfs8hw5jmNhkZhxtddqlMvkqlbrm/OFcBl6
         r04uMViO1yg9vnp8EeYJBDz4F80WX44Shpj9TDCihYsIh3SjwYOrUKiVibwWgf9tWBbq
         g71A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KXCqIMPP0sJrqoBwsh3984kwX7uFxi3cpCqTpMua2F8=;
        b=Oz1dA4CR+Gxx5Nqcpu756AGVoZIJjowps9l/k5aO8EtGTXmUiGr062+dXJZlITJvVE
         tM4PnSxW7LRJ7VXzu5oykjUSgEYv8j90zjeX04J+cp/z97lcFbWSfeiTOqrMnbbLuzVf
         dq3NGLwhzcdOm/oxQ0ZFmLtcKFsM76y3r3X2sNr/CbVeAaUuC4RJQvpu/Wso9ft0Hk6V
         JM5WUv5NIhbgFwOT6B+/ehi1Xy30T3n6JjbV7BIViSoIv5PKw0V6C/FgeJbpHlZyoXw2
         W3YfUNLKrKaQQB+wSSL97vpPujfeWGb0tORnnbrzahlvt6gK9F6KXBhQkCW4R1GUA21q
         5BQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=KXCqIMPP0sJrqoBwsh3984kwX7uFxi3cpCqTpMua2F8=;
        b=q0qCGf4/w5hOkajogEgOClOSIwEj+vW4TC7ulnGh49P/TL2BBtsGUJgFtFOY2EGzw2
         lf6hO18Qf7k96ML4QDcQR7kD/g2Zb+x1RdnKwYZBfgFp/IClNqFU5OPIViUR2ZYz8WeA
         azImfZD9Z1qw1EKGO6Ek33CXuweqcqAX5mjHKC8ki8xZ44YNU+CYqOrAZ4Z+etZ4Lwms
         XkUsBmP8JNx+tKyteJiNZRzS6Tdj2HXT8YfFBMdj+ipZbSkd7Yif3zxNbewsl4QCBcJw
         b5pLBXTHCb4BBDXJdk1ySWIvFv0MLlKindic9/jFnPf6PMgrNo9Mk/jyOFiIHbtVHCtn
         +rXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW60hOHcs551cvLgmnKKobEBtxb3YAhgV+V5CYlWdsTk9xpr8E8
	TbO347UeGEXeJt8RfGf/3KU=
X-Google-Smtp-Source: AK7set91pNg2gHxmrE9XeSojrt5tVKPAhMdGkxihkUWsT7xxa8GReAxs4Xvdh0cd1MZb/UwoWAP1YQ==
X-Received: by 2002:a05:6902:1388:b0:855:fdcb:4467 with SMTP id x8-20020a056902138800b00855fdcb4467mr5997021ybu.0.1677684965378;
        Wed, 01 Mar 2023 07:36:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d745:0:b0:538:4ae4:25bf with SMTP id z66-20020a0dd745000000b005384ae425bfls11260237ywd.6.-pod-prod-gmail;
 Wed, 01 Mar 2023 07:36:04 -0800 (PST)
X-Received: by 2002:a0d:e5c3:0:b0:53c:6e3e:607b with SMTP id o186-20020a0de5c3000000b0053c6e3e607bmr2140933ywe.38.1677684964779;
        Wed, 01 Mar 2023 07:36:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677684964; cv=none;
        d=google.com; s=arc-20160816;
        b=IMxBEFrPN4ockse3wPzRUt5hlU/uzTmVZg/y1Tp+5q8K5QDki1oY253TN2ocBalB+t
         3hRijgEs30la7Ao0JePw/P4p+y9Lb7xlHakf7UguOXtfim3GqMDXiP9ksFm3hpCEsEAD
         1WodPl7kUT7kU3n61QRIRkxRBc+cA8dgVb3l7/M7+PVpRiOqfuVr/zzgW2ff80poRr7c
         6y65OEWs9+ntzuNUAawVBxU1eonvsG/9ic1o7KJah8GMNxYqxkIhF/Gm0Mks5LhH/C2K
         6vgCSz857xvfb0ZEy+D7jrIcXVDHpCpOoU0F9+PMUOu8A69PHV8qbszrgFMC5B+hu1mi
         e67A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gx2Y04HnbVuJVg0xOpO6v56u/oJYu43rVfvF9yJ29p0=;
        b=YsKsztu5tYC3Ssxn8zK0SVj8wIEBkLymkVxhBebdhGk9jf9gXSJ055HBtHipHGNozX
         GkISm/O0EOoxFRUO2jJrfMf8CLOQlQBAeJF42n3roCbJVfEGDaoQiTqrep+bphlRBcTS
         /PhGJoIyINpLqWEKTo1jSCaeiZC0xmuWGbNOlP2dnkxYDeyDTVjkt7uZCMPFym/qhSxA
         SUVG+VrcWc9SaQLSY1CdK6oVu3o54pY0k/EiGKTjyVOeE4ivKl6VX7om7+soC+dacjUk
         z+jjS7kVcwD6jHgr5OKBAbjF1cY9RAErih11vd2wFnErmFL5lM5Hi+tpR6x9sfzi5M/5
         1KOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pF5MsrHt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id bo5-20020a05690c058500b0053421bb7e79si1301766ywb.1.2023.03.01.07.36.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Mar 2023 07:36:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id bd34so8193255pfb.3
        for <kasan-dev@googlegroups.com>; Wed, 01 Mar 2023 07:36:04 -0800 (PST)
X-Received: by 2002:a63:741e:0:b0:502:fd12:83ce with SMTP id
 p30-20020a63741e000000b00502fd1283cemr2277016pgc.5.1677684964298; Wed, 01 Mar
 2023 07:36:04 -0800 (PST)
MIME-Version: 1.0
References: <583f41c49eef15210fa813e8229730d11427efa7.1677614637.git.andreyknvl@google.com>
 <Y/7VeHQBL43MzIPR@debian.me>
In-Reply-To: <Y/7VeHQBL43MzIPR@debian.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 1 Mar 2023 16:35:53 +0100
Message-ID: <CA+fCnZdq0FkQDe+FU-dUfsBFnQz-xqRO1eUJ3_Oq38OuN2N7zg@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: improve documentation
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Linux Documentation <linux-doc@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pF5MsrHt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Mar 1, 2023 at 5:33=E2=80=AFAM Bagas Sanjaya <bagasdotme@gmail.com>=
 wrote:
>
> > +2. Using `KCOV_REMOTE_ENABLE`` instead of ``KCOV_ENABLE`` in the users=
pace
> ``KCOV_REMOTE_ENABLE``

Will fix in v3.

> Otherwise LGTM.
>
> Reviewed-by: Bagas Sanjaya <bagasdotme@gmail.com>

Thank you, Bagas!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdq0FkQDe%2BFU-dUfsBFnQz-xqRO1eUJ3_Oq38OuN2N7zg%40mail.gm=
ail.com.
