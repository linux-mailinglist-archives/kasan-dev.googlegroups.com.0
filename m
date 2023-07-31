Return-Path: <kasan-dev+bncBCCMH5WKTMGRB46RT6TAMGQEUXBP6LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id E27D5769D85
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:01:40 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-1bb67d16387sf9065021fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 10:01:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690822899; cv=pass;
        d=google.com; s=arc-20160816;
        b=nOc3V2hzbYFOD3/6elAZyjZooEhx+VTP+jYsr0Q4GsLWQXtdATUpv3ewGJ6gbYjhlz
         vVtKvhCI99NuOTf6MQyy9KXnbuD7HWngEUat1trJZRbfp/dy7Dl7wH1cH5+E/D5MB2NT
         z5OGDnMpy/3fYkPmCi2vEjA1PRd4zN/Rzc+kb8AQtAcpwyYgn99PwCsMOGfkUMRgpqZJ
         +38wjgMvR2WiRg4q1F5TYRGaNn+aELXStCI8RfMFTXi/OCiUZ/tYhE6poZP90PM6QFPK
         Gq7vWnG+CINSJ1tI9W88Xr3AT/+3/lp9jPUK48K2Fc8fPr7xNYvIG8SdbZHOEbuWe/2y
         PoAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6EpWJijg57g5q7b/1Vpb9vIZk5HUz1z5ika+L4EPTt0=;
        fh=FpmOSBwjI87+MAeyVxOnHPZs0VsW7pD6MuuYSDRIGhM=;
        b=x7v5KiuJCUsjmnal0AEJRYt6iqoxWkYIgvQjx51DNgr88JgZnhp+tTj0G5w8yYUiOA
         jW8CqpHafMPgdQ1bO9qW4d120J9UsYXxuzmjGsHkH0/Z+swKgutoafpXWoLj1tqaK8Ji
         Uxu3kfjBxURQ/8qJqENnk3Y3aA0vn9QyK81+2YC/MWTy7V+hZ0ZPkODrd2lfO2hoAFDW
         oe8n//I0gQuM2njru5TaiXbUE1N9DaOXuVToVY6LOf0HtTnUiKLyDeE+6PxfDlFRVgqo
         kpAiLnvAAhZR0qihPjD6kQ/Ejk8t9IiaTyLWmG4JZxNHbRBJMHv7vRz/hRW3q35jMfSQ
         0Y5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="QGyf/Uoh";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690822899; x=1691427699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6EpWJijg57g5q7b/1Vpb9vIZk5HUz1z5ika+L4EPTt0=;
        b=S3mFSiwDCEeoGEiwp4HHAacIQIxFbHfVPPmbboTp1VHAMgiOZC4eRzQcDVEz/OCI2K
         KgwHu6S+30SakXLUIEWbMd7+L5rbWOcsR7+8aq1mJUMPwZSHjNBxRUBMPSpVPbR/Itun
         1PvEa2MHz4OvonNYgc+1CXqfYH/C/oux1DBpK1KpQUaHU9C5wcHpgUJbrpLH/TypOxo5
         fWz97NOa3utNOJHUwjco08RdV78XuVtdQPSBEZC/lSZ5OqzNOq+Ev+YFPWlyaKXRRyU0
         fuvFufbI0z6OyXhJUd5CAL7ViIa8kQDxD5TtP7NcvmYyCKlRfSf6CsCuJEeNg1FJRm1/
         K6Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690822899; x=1691427699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6EpWJijg57g5q7b/1Vpb9vIZk5HUz1z5ika+L4EPTt0=;
        b=ajKGQN56dfHpHhdTZ/bph2dRPdc3d1SF5yi9SFA1h8d+WviomFX/rlz2ItiF4jZzB9
         kz89iuLP7fOG0yn5b16e+TKMRJZL0HQg/r8PuL4eh69e7AEFskkBXmoJ7kLL3bxe1jcr
         mZk+CcEBceWFzhiSo43DEEcbnDLjQPBlNnjAMyv0tHPFPM85LfVYDeCpKRlQd/+zfi2S
         1nsHBRBcSfMIxGVzREhU2PNJ1wbf5E8ySf+R3Bk18rekRwbDD0Md1Fwv7CNj7bOlguN0
         wA4qOeE/NhxYa6Oyf4N8Cfm3bhGbTwM8xKajq2iZNx2l94GOWKQ00zf0jkhWYZfOG2pP
         S/iA==
X-Gm-Message-State: ABy/qLZbI70/9rDmhUkX+qe/dIoR63Xn7VJTVzYTisbWcUEzgBdWs1uC
	d99NTRUEy8oMQg9DurkC0Bs=
X-Google-Smtp-Source: APBJJlGuF/ImR7pAbl+aJjm/ZH6N3FuzPlzXlHdvY96LtdRudmPqCnKu9hLBYcea43uL8QIg+wI14g==
X-Received: by 2002:a05:6870:6110:b0:1be:fdae:601b with SMTP id s16-20020a056870611000b001befdae601bmr1285278oae.52.1690822899287;
        Mon, 31 Jul 2023 10:01:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5202:0:b0:56c:d455:5430 with SMTP id d2-20020a4a5202000000b0056cd4555430ls1021248oob.2.-pod-prod-01-us;
 Mon, 31 Jul 2023 10:01:38 -0700 (PDT)
X-Received: by 2002:a05:6808:ece:b0:3a1:d1d9:d59c with SMTP id q14-20020a0568080ece00b003a1d1d9d59cmr12788735oiv.33.1690822898324;
        Mon, 31 Jul 2023 10:01:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690822898; cv=none;
        d=google.com; s=arc-20160816;
        b=VnYG1VE7/Uggc/GLOubRbzAXuHlBLexP4Q6SgZ0uFHBvVByfnWFzRQXGXOjm80aSWC
         YD4chJGrAeaB5ilipoJareeVRjcHQqyXpxH4493vn3Mn1AXPPY+5nWYJvtrky2adqTe5
         GpT38SNiJ8tjDQpbnoKv6c9/Y6YQi4NDJ1IwuFU7NzNqBlFs3LERDrWmTnJpuv4hrkzl
         zs8H8XuLafF2el84GszS4K7F+RRHcm4rlr1edkwqujni33Wgfd6iEHz0CQvjIJE2SHT1
         jLM5IWqwuXYsUq7B5Ftz4rImZ9DCrvMMuSOAxbb73+CccY+9JyMx43ss0Ib8gUPZJqAC
         XvIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=E23qwAQJvXasIhgQsW92y++GdBjVpFQZpVbqevq6H4Q=;
        fh=/L/BfydENXJ5eWZhj6DuxRELOnbBRK5NL0Fx2I2Ns/k=;
        b=VRIsd8krwRd0zpuftSa4mdahrvDCKMbUv9zJ9NxG99suHJoRkpIygWT/pK13ZjruT+
         b3ObceiR64a2QfqqoG82On+u2ZTJuxBXVuPNEW+m6jgVsLcTG4pQzoX+AVC1gp+icQR1
         KE/IwGjet2gmdycPArsBGDuNoHvrKPPkdPZZpl8RUxPa3GKNZylDIlAZmVYbUKK16bbs
         IjRmnfOggbiL62DWWzyt7VvgB8DdiMkfU+uhNbrcNkuqebbLYDaarbrtZKjCVpSEw3qk
         tswmmmOT7IZMAb2cCn4YqMKnjRA4BodEI6HWAWncJQWfDLKkLuoejJnYwrDyw7neFD68
         EaIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="QGyf/Uoh";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id bv10-20020a05622a0a0a00b00403ec96ad23si758247qtb.3.2023.07.31.10.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jul 2023 10:01:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id ca18e2360f4ac-783698a37beso254207039f.0
        for <kasan-dev@googlegroups.com>; Mon, 31 Jul 2023 10:01:38 -0700 (PDT)
X-Received: by 2002:a5d:9149:0:b0:786:ff72:8da8 with SMTP id
 y9-20020a5d9149000000b00786ff728da8mr10356593ioq.17.1690822897680; Mon, 31
 Jul 2023 10:01:37 -0700 (PDT)
MIME-Version: 1.0
References: <20230727011612.2721843-1-zhangpeng362@huawei.com> <20230727011612.2721843-2-zhangpeng362@huawei.com>
In-Reply-To: <20230727011612.2721843-2-zhangpeng362@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 31 Jul 2023 19:00:55 +0200
Message-ID: <CAG_fn=URAW7=utEcN1Hs9G0mBsBGCA-R71PmzaVnWCNp-2rVgQ@mail.gmail.com>
Subject: Re: [PATCH 1/3] mm: kmsan: use helper function page_size()
To: Peng Zhang <zhangpeng362@huawei.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	wangkefeng.wang@huawei.com, sunnanyong@huawei.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="QGyf/Uoh";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as
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

On Thu, Jul 27, 2023 at 3:16=E2=80=AFAM 'Peng Zhang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: ZhangPeng <zhangpeng362@huawei.com>
>
> Use function page_size() to improve code readability. No functional
> modification involved.
>
> Signed-off-by: ZhangPeng <zhangpeng362@huawei.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DURAW7%3DutEcN1Hs9G0mBsBGCA-R71PmzaVnWCNp-2rVgQ%40mail.gm=
ail.com.
