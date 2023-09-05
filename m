Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBFMC3STQMGQE4MVVIZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B35ED7921D4
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Sep 2023 12:21:10 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-31aef28315esf1195365f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Sep 2023 03:21:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693909270; cv=pass;
        d=google.com; s=arc-20160816;
        b=WF7c9ps3rM7hXWtVs2zYNXAtU+g4KceAGCPO/70Uq7sv2ntZRpEh/iDf3oWwf/iXy5
         +WpTg2e+A8IOKg0vtaTiJKdPbR7yJgvQTlds8lxccTwz7PRVe5MxppC2vs1hSaPVM+qj
         G839utZpLOk/c+wIxrqLs4bJoyVUXEvUkLSEg1KwFsJErVn/SMa5z8HHuqtRAeb05z/b
         80SJqvFwfpM8LedstgG+/TZ5s04CwROiK+Sdz7XO1DDz+Sffh+01+s5HbfpSG0qt1VFs
         UOBfSsxWm2wMiA1OYTd9T3aOMdRZZm+a0D0XKYpDp3g20XY0gYBHsBtYplTzMqcZSdh2
         GuDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3xx+vAZRnlf5sizTPFObyaNBoDOZ1n9+/qbYookMAjM=;
        fh=6lLeuQ7uTW1dKJNcoHu+kLOXh6npzId1DdRHaQfM1RA=;
        b=gKohBpbqFZV5PbQO1lIApSsUD5/KbBSf82npwdNysSC9IDmNyF0tAddpD6f16mf8f+
         J7XoQH6xgNijurAj8Y7ou5nsPbb5JegAPw7UfsD2jobgbRJVPhGXKVSUNZa1eSG3gwHY
         nTP/OM8QhWKN/7pwneow9b+zSCUKTt2ncRmEjPwxKUdNaCeXq0FtnC1xSwqO3WdhXQmg
         +xk5UYdRoDYDGBkO/nOKwF7CfbDUdJEWbn5q4dA6kSJrjSOuA+Vv6kGpHWbq8FXETB3a
         lihaHH7Rze8tOUbYhWh2h8LtFguKxQwLoswv27Xuvbk1zvhQ+X8bJLfl/5uf4Jmm79ks
         KVyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="V/FBhenh";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693909270; x=1694514070; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3xx+vAZRnlf5sizTPFObyaNBoDOZ1n9+/qbYookMAjM=;
        b=rPISdLAo3gSI9LV2ZmldmBk2oyMXfDISPdBuiaSvpiZ5tawITQfNyU3ywawpOV86r2
         l1qwQooiYUe4+o3+6tQ+6U4CB96Nw2kil3f4S+a8m8FfJvIJ+G3FXTFxNbAM0YAILDLz
         ditdRWH7CvBmD5YjAsmS3C8tJ9qi5wylvjt1rRws1+Gs211mOykXJvbe8+9xt1eVORcF
         s50EnIqjYoaGf++gqguFdLm5ZrAuHcvHeLu2FbsIB8+mxQcugYzBWU71w0VnUzPY0A8x
         v5Ktq38q6hViq1PSqAC4g2rvVHx41pG0N/epIoXPZsKscIawb9f7zkYSmCdpm+7/AA/d
         hWTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693909270; x=1694514070;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3xx+vAZRnlf5sizTPFObyaNBoDOZ1n9+/qbYookMAjM=;
        b=ZfZcw+ADCGzouZh7oZ4FkQpYMnH45UYq5GAKcuvBZseO3yuOUUrbZefbYLuGd/k6Yd
         QkYtbND3VoDA9JP1kub5nwpMZsKGN0uh/whtYO1MFgBFLQh8pKvWhvrp4BfuF0kEVcRc
         07zKt8HCif7S/3xVTvMyCLA3GSacCWle3nOszqLIEFVfYOdHsc9LiHbDa4zLc4hTt8Bq
         B1QSYcpHuBN7ehbGezv03p9ZXrWJm5KLQkPmt3+f/ZDGkyoQZdZFaB4ZTY5z4d7hYtaS
         MOgRLg/NcsKp8i5550q3RUwfFWvVU2jchnBjuas/hfpAbRN/mIju9cC8Iknma77o7iqu
         J90Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxEliZoaoFWIPNeTOrNmT+JBjITFCYnvtzjGFv4jeCon0IP9BZ3
	uM8afLrZarWHyCYqckZ54O8=
X-Google-Smtp-Source: AGHT+IETQAYzN5wTdwfL2Z/DIrnpPp+xbONJjkVTRfjorbPc/tn20t73NUSOVYZzFcn7b/H+gPxI/g==
X-Received: by 2002:adf:f288:0:b0:314:10d8:b482 with SMTP id k8-20020adff288000000b0031410d8b482mr9683384wro.65.1693909269958;
        Tue, 05 Sep 2023 03:21:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ff87:0:b0:315:9d1e:ee24 with SMTP id j7-20020adfff87000000b003159d1eee24ls1520879wrr.0.-pod-prod-06-eu;
 Tue, 05 Sep 2023 03:21:08 -0700 (PDT)
X-Received: by 2002:a5d:68d2:0:b0:319:841c:ae7a with SMTP id p18-20020a5d68d2000000b00319841cae7amr10202341wrw.41.1693909268240;
        Tue, 05 Sep 2023 03:21:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693909268; cv=none;
        d=google.com; s=arc-20160816;
        b=YAvhvvhXBNPqK05o54v5/Nb2RcdH/+c2W3pMUH4nO0Ixz6KmexrM8efFfVjUHR/gHP
         l8SznjzcMnkY5TnNhiXwngtMChE+QCCJlnbWx8tSArTXuHqUYu0H4V/ZfbY0ZVtjsdun
         m7FD+oMEhbk+O4MhSGPTxwsw/h59toVEeWE3UwJeMYH+40NOZusqtTyDtFDZ2xycF2xB
         mhIwikCw2Xf3vBNBSdEiIYqBJNGtyVGNlO+kMkMZjglyNRMAVRAnAMUyrt0hZkqqJxg0
         7qERwSRBMRqnrcnqZvlSDll/s+64rm1yIYCVqSWrFIfTXhshYyZ1HxbJZg4DIkiorkp3
         qKcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NwyqToqYJJwMOPPDzFYG+9uYGB1Ne/sb4Xyofq07vVM=;
        fh=6lLeuQ7uTW1dKJNcoHu+kLOXh6npzId1DdRHaQfM1RA=;
        b=jvvDG6Vq0O4aF/02MbZiujFOb520znY4ayRUf8nMH9fsvzwvDPdlqvzZB5WQfjA94D
         qLOzsmirvubr2VmuKNHNj//y3vyV1MhvUv7sJ7C7PGeg2MIMLv/UYXXus2Ya0ktS6Nw5
         DapKEvlLdonsrvfHZ+MbUr2gXe3xzFOezdfsq0JpCQ90u8wyNEo5iv2a6A4Brdj61UgJ
         2n7oBalYXSDG+DfQITQb4DbOUVbGtuBPzEPR85Hg5ea0zc8r2MPCpULb0EYPYaMWnVko
         O4qliwpkKP3+1wg1Yrtb9RWA73jAaBI6//jKZbXIzTQMBXTCk4U0lNrMJPEcXsMYtJk+
         T9TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="V/FBhenh";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id h15-20020a05600004cf00b0031de9b2a3b2si889421wri.6.2023.09.05.03.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Sep 2023 03:21:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id DAE2AB8118F;
	Tue,  5 Sep 2023 10:21:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 22BE0C433C7;
	Tue,  5 Sep 2023 10:21:06 +0000 (UTC)
Date: Tue, 5 Sep 2023 11:21:03 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Lukas Bulwahn <lukas.bulwahn@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, llvm@lists.linux.dev,
	linux- stable <stable@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	eb-gft-team@globallogic.com
Subject: Re: Include bac7a1fff792 ("lib/ubsan: remove
 returns-nonnull-attribute checks") into linux-4.14.y
Message-ID: <2023090548-flattery-wrath-8ace@gregkh>
References: <CAKXUXMzR4830pmUfWnwVjGk94inpQ0iz_uXiOnrE2kyV7SUPpg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKXUXMzR4830pmUfWnwVjGk94inpQ0iz_uXiOnrE2kyV7SUPpg@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b="V/FBhenh";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, Sep 05, 2023 at 12:12:11PM +0200, Lukas Bulwahn wrote:
> Dear Andrey, dear Nick, dear Greg, dear Sasha,
> 
> 
> Compiling the kernel with UBSAN enabled and with gcc-8 and later fails when:
> 
>   commit 1e1b6d63d634 ("lib/string.c: implement stpcpy") is applied, and
>   commit bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") is
>   not applied.
> 
> To reproduce, run:
> 
>   tuxmake -r docker -a arm64 -t gcc-13 -k allnoconfig --kconfig-add
> CONFIG_UBSAN=y
> 
> It then fails with:
> 
>   aarch64-linux-gnu-ld: lib/string.o: in function `stpcpy':
>   string.c:(.text+0x694): undefined reference to
> `__ubsan_handle_nonnull_return_v1'
>   string.c:(.text+0x694): relocation truncated to fit:
> R_AARCH64_CALL26 against undefined symbol
> `__ubsan_handle_nonnull_return_v1'
> 
> Below you find a complete list of architectures, compiler versions and kernel
> versions that I have tested with.
> 
> As commit bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") is
> included in v4.16, and commit 1e1b6d63d634 ("lib/string.c: implement stpcpy") is
> included in v5.9, this is not an issue that can happen on any mainline release
> or the stable releases v4.19.y and later.
> 
> In the v4.14.y branch, however, commit 1e1b6d63d634 ("lib/string.c: implement
> stpcpy") was included with v4.14.200 as commit b6d38137c19f and commit
> bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") from
> mainline was not included yet. Hence, this reported failure with UBSAN can be
> observed on v4.14.y with recent gcc versions.
> 
> Greg, once checked and confirmed by Andrey or Nick, could you please include
> commit bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") into
> the linux-4.14.y branch?

Now queued up, thanks.

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2023090548-flattery-wrath-8ace%40gregkh.
