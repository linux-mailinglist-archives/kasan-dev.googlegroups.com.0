Return-Path: <kasan-dev+bncBD63B2HX4EPBB6X76L7QKGQEYB364TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8759D2F2196
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 22:15:39 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id z20sf160716pgh.18
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 13:15:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610399738; cv=pass;
        d=google.com; s=arc-20160816;
        b=QDgMR7PMHNx+gH5c4p4qvZUUuG7MGrqQFfwK5dv5ykiZJiAj2e5opDxSkJPD/4Wbou
         7tRuwYDdfWIGcWPd3JRQh3K95c+glWcqhDLA3zjOYqYIpYXOk0FDxfeGCWswGR99oK6+
         +LoTLS00mLIcNDb3ld7HrrQVHPer3mDY1IaCEcfM3cf4as3nsnI2Gnj0Emxrd4CAcRzA
         DnKUiRJ53peUVpDCmzEPITdKQZAu3JcftPXjSSFx99y4Zu9DJmqFX75NPsxYQviL5OX+
         rezl1gs4p9kH+6XImJHJQYLyJURJl3t5cUR+hHiuk/18YYN3sE8PNzqhKUhGRPm+bvwi
         unpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=GCTQe/Q8rqPHmBg61zLz4fpEa991uwuNlGq0U21L3uo=;
        b=wfpLCba2RUPHMnhvMuG1uh1oNj2SsiyScEoVBPzPZ9mIuYSd9eKMx/4/n/spR93crV
         plIL2/aZUu7G1650NS/XNbv21lG9okRck5crnz3g/A6/IAfIA6B7xr7umMPAd+bIpFcG
         BMDRW7Ajn1aEqYfyuwdSKDIXJog98G7X0nIyMgfnWG+WPpG3OwP9ueE12XGMWqSDMh/+
         fkCrRBvqctdqb6/yrHDzcRbhETkBepLJedxE+aOKsQGSeP+HGsN8d+fiErdxrfKjYU9V
         fHMn5RCy6fdHFsNRBj5Obs13GIA9W23Mlxn8fich0gk4CDHboIXAh96VDBcqvHPxqxIY
         A+ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=R45U2GFx;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GCTQe/Q8rqPHmBg61zLz4fpEa991uwuNlGq0U21L3uo=;
        b=FoCoB+e8wWON74uhWzpwPPmVjQirqf60q2Gk+m3DC2XIM5gq1MaboH3kAlWtSZzYJh
         AGSW9QuY93TZ5UoGS+cgMYA52cVF/18G0qeKYNIx4Vs/b68fmUoTboIhE5RpZaPRW3Ty
         fwHXnCBqiZ1rQjR8XoDJ6oaXGsiCEcapzeOaFg1V07zHsFGjBQRSs4U2uIz/HYizSUwE
         bP1BcTHfQhhRQ010f10lxwy7gZtNxp+IBWpb3GIl8CxKdTPqgpz63aeQB724gi4ntAnD
         7x+k/K63uX3SqRMKK4b6Av6QiUnIKqssNJrNVsc5X4DkXZSObFSNFw6qwLOajkVHYvpZ
         xDXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GCTQe/Q8rqPHmBg61zLz4fpEa991uwuNlGq0U21L3uo=;
        b=VpbEJOglrJXtHTQtX6bbgKFZ6A479RYu4lvlZ7f9SDeMgjTsfV9Ha1lGDRCKCQyqec
         PFwh2Ne7sBoCBYPKcPPf6Cq62M7lmlBvuQg8udI3cS7fegJoA5JXNPWhzcvn8xRnG0bq
         kwQ+Mv890Vw+xOEjkEMVblITdUd5XwaGvzo+gQjZiNDY+HIQ4fM9YKfGcCLXTM9g69+S
         CKlyWxdy1V8Ajm52b6s0nAfVTOv97vhI6+IXlHkS4QqSsHzvCkNPkmQ0JebE1A+v1Mkl
         6ZlS+MV/Wge08iRfgvUnIZUGZPGvxYSmemIlbI9sgcC9fqsfdapR1AUhmP6zOmnp6gok
         Rbqw==
X-Gm-Message-State: AOAM531wBOP5f0hoePqCaqeDYylkM82erik3aGUrc89oFzJf/y7qFyED
	Y0GYuYYJQpflQBKK4F8JSvQ=
X-Google-Smtp-Source: ABdhPJyCY0RAd3hak4itKiY84eWZS7W4SgVGL4sDf59Cdvpau3yUU1elwO39RFL5xd+Rg4JJm6MamQ==
X-Received: by 2002:a63:da17:: with SMTP id c23mr1378188pgh.348.1610399738299;
        Mon, 11 Jan 2021 13:15:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e287:: with SMTP id d7ls234834pjz.0.gmail; Mon, 11
 Jan 2021 13:15:37 -0800 (PST)
X-Received: by 2002:a17:902:d34a:b029:da:861e:ecd8 with SMTP id l10-20020a170902d34ab02900da861eecd8mr1173439plk.45.1610399737433;
        Mon, 11 Jan 2021 13:15:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610399737; cv=none;
        d=google.com; s=arc-20160816;
        b=j5l6uwyU4WxfGgA4TLcdFnCEX3he8DL5ahYphxCuArC8bvH/6y7P0OHIBSpOqwBmPR
         dekh1QJvPMfyoxfECLrddh66Q6/q3ZJQen5sgdEAP/eKFvKReLM8z4wUdv1scZxbAGLu
         L2foNKjmv5uNcNeHvS8ROd36F54Zzx3I0xiGeH2tmGd7zjlQRWhFvHdHtPx2hyNqhGuI
         rGzbj62FC7L8YIxZjNYXYffzJZGJslDzUzL6tzzCyWD+WI9a6ICZz2BzQP3+bkFVzqEQ
         xcOAKAh/84i4RRHcNgfXDh+3w3ml4Ne2V5YA7pec41Jcs5XbE63tibvhe2MsmBazmYcL
         VaUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=eImIXVcmQBsUdAK4nUs3QzMFY2oOA0m3xFBAZ5UlarY=;
        b=tcHYv8bl281tQrAPRHm8CSsxywjO7WApfQycVw9ereyOoGQtLvzTfvKYUIHWaMnJF5
         D13/Cx6t1Iuqt6Lo3K3Syqt5HpbVF8njXCcGuRJ4aDSRvElwk5QTX7XdnvtyFYTsOA6z
         wjLCJC510snd98yxqqRMDxGPmpM+lr19lrgm6pCztIpN2/tlu9wv7F7bN2xpUbvJbupg
         yea6si56D2sGeg7UHu9q6k8RE1Pm7qm2G/JCz60vGL+/Sm3OJVmL23S7J39eHRpPBLzm
         gkSM5msrwwJUArPnCwJnPAoTkJtmf0nWA6mTWOQLjVp4/DNMtYl9BQrs1XXK3W1kmg7R
         cf6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=R45U2GFx;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id w6si36000pjr.2.2021.01.11.13.15.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 13:15:37 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 30so485407pgr.6
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 13:15:37 -0800 (PST)
X-Received: by 2002:a62:2585:0:b029:1ab:7fb7:b965 with SMTP id l127-20020a6225850000b02901ab7fb7b965mr1308806pfl.2.1610399737104;
        Mon, 11 Jan 2021 13:15:37 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id t4sm526934pfe.212.2021.01.11.13.15.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Jan 2021 13:15:36 -0800 (PST)
Date: Mon, 11 Jan 2021 13:15:26 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	andreyknvl@google.com, jannh@google.com, mark.rutland@arm.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH mm 2/2] kfence: show access type in report
Message-ID: <20210111211526.GB842777@cork>
References: <20210111091544.3287013-1-elver@google.com>
 <20210111091544.3287013-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210111091544.3287013-2-elver@google.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=R45U2GFx;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::533
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Mon, Jan 11, 2021 at 10:15:44AM +0100, Marco Elver wrote:
> Show the access type in KFENCE reports by plumbing through read/write
> information from the page fault handler. Update the documentation and
> test accordingly.
>=20
> Suggested-by: J=C3=B6rn Engel <joern@purestorage.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: J=C3=B6rn Engel <joern@purestorage.com>

J=C3=B6rn

--
This above all: to thine own self be true.
-- Shakespeare

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210111211526.GB842777%40cork.
