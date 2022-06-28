Return-Path: <kasan-dev+bncBCF5XGNWYQBRBA4G5WKQMGQEWOPZ44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AF6B55EBDC
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 20:05:57 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id e205-20020acab5d6000000b0032f6c02bea5sf8272540oif.9
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:05:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656439555; cv=pass;
        d=google.com; s=arc-20160816;
        b=arlaJs8XFXLmCpuVUKm1Wux2HeSQwduX6KB/zBRfyyMDoQg9uq5oPUamDOwa11Gv7k
         lOwqWqgl2y1Vh1EX//EPVYh5X/1Kba4zjKKeXKjZiepEYDO2rPy8z/lEaLnhIdrx491A
         SOjSYUNK1NzpGRcX71c4qU0U80Zcco8L3w+iqgfmAl/vbaYfTC2ipQfH44QfjLtkPs3D
         Wa8t54EgVsUx3N4cwVlovItYfjZBL8ko/ppAxj8Jvi5Oiz08fk/UodoGjIux+nF5vZdC
         CS96ytBHZUthq4JGA2lyCMBzv8JpPgJecrg11z2ZXyRf/VOCgYw4Y3velwWKDCrb3bIV
         a+yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=B22GS4vey28js7NX3sXKjORY+0zH/Bf93FvBhv13Vsg=;
        b=lUYbLN7T3FHmp/PurZDnohliTG0VHW145mecHdvJeJ0dJrJLeu+4O78+9G8B8HdO19
         tsl+eFApbWAcT/X9W8DfLwA0M7+8SbjygGWfiGDxy9CFRCkui7hdQHZjrC3AA+tVDcD8
         aWZ6wIFUe/xQgNJKtSKHORsV+1/XMxKP8qdBG/bKdTuWdrgG1XciduoGt6E7QdYIrHmG
         RCYX8sLKBmuUutTqgR5NNM/Ww9HuK5KWBFawsow9M7W6143UorkXAGFgwloXpQCgRnQx
         q9Ka1JqKy5zljmkckjijDRTtRrirtwreotNZN0FqNjHMnzepwdjSEXf5yxoWG1jIE4km
         O1VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="F/CZTCTD";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B22GS4vey28js7NX3sXKjORY+0zH/Bf93FvBhv13Vsg=;
        b=gghhZI1H2RzRXnEW98ALuOvLkzLhG8UnrSHxsFOBOmOEBAgLnsbCoitBb4wgCMBCti
         nRIWBVWhFTbNvYfkkznI2JgIbIh9mKwKC27wwncUp4J7+MLZlu2EOe0RsomYGMkpweuM
         nY77JeyQlIUu245AIutH2tNoy7H+p+4oPOmlNj6I1POn4VU5c4UBYh+SkNjcFVu2Jvt8
         cFSCbcyqMg9QYrL39zf0fazYLD1fID+Rnla1RmTKZRPlZhEjTIaOXGgviejqaEC1UwJF
         JHhr1YsbHuns+duS4w4abtEV+7HF9g985G4vMaAvQDaluLtNwKtUZeAoXvnHgymy9Hj8
         zm+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B22GS4vey28js7NX3sXKjORY+0zH/Bf93FvBhv13Vsg=;
        b=Lm67Ht7x0VVh7vIWTw+MpAIqJ/5m3qKGXnVN/Jf9JIMc/axabSF20jwPJkCjrzCHl3
         0Y60SDSRbA+JluWltOF/xsdrKV1T6i4LXT8a/XfZ+daNnNJno0adf5Sp1tc+NiCI3Tn4
         nYEqheBLIYzLdd+C7tPLU3H/bxABav5CjtcAohhc4LmW+DEhQT9SkN5TPBi3lO3H/N77
         32+p4cNjLp2W9/jteF+Jr3e8e5XxSBOZXuwb+aNpqwafgRJgvKCZotQNGyGxxJwyl4/P
         uU1gYb+kI8Hrg78gF9PICnE0gURAZz3nH7IQwvuoY0/rDVAw4WfY6fyB8hc0adeTMTs0
         POUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/FbBz+GSA25g52JrTHSq6tR72rkh3MAZsEQ8690pnxdogUzKM3
	AfokvVFPWZ95B+jjqFI6K+o=
X-Google-Smtp-Source: AGRyM1uVtuHlQDLhDMay2Je/uFcBRyRulKxOuluP0lhxZzW+jZfaE3sbcnHuxBMPv3RxFknUxHGl5w==
X-Received: by 2002:a4a:b149:0:b0:41c:12e:c77a with SMTP id e9-20020a4ab149000000b0041c012ec77amr8665074ooo.5.1656439555497;
        Tue, 28 Jun 2022 11:05:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7384:b0:101:fb02:8b87 with SMTP id
 z4-20020a056870738400b00101fb028b87ls9065233oam.1.gmail; Tue, 28 Jun 2022
 11:05:55 -0700 (PDT)
X-Received: by 2002:a05:6870:d599:b0:101:652e:fae0 with SMTP id u25-20020a056870d59900b00101652efae0mr478506oao.285.1656439555019;
        Tue, 28 Jun 2022 11:05:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656439555; cv=none;
        d=google.com; s=arc-20160816;
        b=iSdW1JEw197bfYh+ZVx9K4T1746B0xk0e+8vKTH3gh8HNuE9nE26ZNZHaDQKKPDDN/
         asnlEFQbxWLCr1M9AWMgv8FikR+KEGBm2ZOx/dfhtcYgBhViSjcDYXzp/iVHgdtj2fqM
         ueAtW7XRpS8De6kY2w/Bx+gf/AReDqz9NiYSkrl+tV1/jORAvo+6zZUhhTPlDG6rmcC2
         IJLdY0x9QGLrWmurait3zBt/+nQe65b3WGf4GJg7Mreo/BzLAymBdyqRq9Tz42ajN36P
         UzthA9SK+W7AD0HVSqe7mXEIJRAj8mOFVUWmwLXGEM9t1GmLdf6OaHkGtI1yeSeDtlyE
         rwzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=pTcGgtfSu6n7KkCWKQ4ciWe5XeKK5S4riO8KfNVW7Ig=;
        b=vnpr4lDyMFXJJEP2UFnPe8jTsX0dmoe00epjRp4WP9diO82L6DgOISYbvk0isN5ERr
         wbZDds8qhXCIQ/OKS0VUw/f7oQM3XIizf+V34GHH9k56z96GVUTo2VebhOGe+PM24llj
         5NF4IzzMnMPDgPTEKCEf/7snMt32lLYYgCubVEvGYZ1ox9ZpQpYD85YhZs0zO1RPPCY1
         J2hgQnc91g6JLXW1jdBGLH/gIKmPE4LuUhRbggu0PbeDMgYJe65hBIivv1Vx4Nz1ja3I
         Ltmvaq2PzS8tvRzyZn1y8QofIPSQK181Le6h0g1WGgzgTQ4yvwu5gP8ZtbttxLZE9Fwt
         Rkng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="F/CZTCTD";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id g5-20020a056870c14500b00101c9597c72si1913403oad.1.2022.06.28.11.05.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 11:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id k9so3483129pfg.5
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 11:05:54 -0700 (PDT)
X-Received: by 2002:a63:7412:0:b0:40c:fa27:9d07 with SMTP id p18-20020a637412000000b0040cfa279d07mr18441815pgc.27.1656439554674;
        Tue, 28 Jun 2022 11:05:54 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id i3-20020a170902cf0300b0016a0ac06424sm9669985plg.51.2022.06.28.11.05.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jun 2022 11:05:54 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:05:53 -0700
From: Kees Cook <keescook@chromium.org>
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>, dm-devel@redhat.com,
	linux-m68k <linux-m68k@lists.linux-m68k.org>,
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
	linux-s390 <linux-s390@vger.kernel.org>,
	KVM list <kvm@vger.kernel.org>,
	Intel Graphics Development <intel-gfx@lists.freedesktop.org>,
	DRI Development <dri-devel@lists.freedesktop.org>,
	netdev <netdev@vger.kernel.org>, bpf <bpf@vger.kernel.org>,
	linux-btrfs <linux-btrfs@vger.kernel.org>,
	linux-can@vger.kernel.org,
	Linux FS Devel <linux-fsdevel@vger.kernel.org>,
	linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org,
	lvs-devel@vger.kernel.org,
	MTD Maling List <linux-mtd@lists.infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux MMC List <linux-mmc@vger.kernel.org>, nvdimm@lists.linux.dev,
	NetFilter <netfilter-devel@vger.kernel.org>, coreteam@netfilter.org,
	linux-perf-users@vger.kernel.org, linux-raid@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	scsi <linux-scsi@vger.kernel.org>,
	target-devel <target-devel@vger.kernel.org>,
	USB list <linux-usb@vger.kernel.org>,
	virtualization@lists.linux-foundation.org,
	V9FS Developers <v9fs-developer@lists.sourceforge.net>,
	linux-rdma <linux-rdma@vger.kernel.org>,
	ALSA Development Mailing List <alsa-devel@alsa-project.org>,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
Message-ID: <202206281104.7CC3935@keescook>
References: <20220627180432.GA136081@embeddedor>
 <CAMuHMdU27TG_rpd=WTRPRcY22A4j4aN-6d_8OmK2aNpX06G3ig@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAMuHMdU27TG_rpd=WTRPRcY22A4j4aN-6d_8OmK2aNpX06G3ig@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="F/CZTCTD";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434
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

On Tue, Jun 28, 2022 at 09:27:21AM +0200, Geert Uytterhoeven wrote:
> Hi Gustavo,
>=20
> Thanks for your patch!
>=20
> On Mon, Jun 27, 2022 at 8:04 PM Gustavo A. R. Silva
> <gustavoars@kernel.org> wrote:
> > There is a regular need in the kernel to provide a way to declare
> > having a dynamically sized set of trailing elements in a structure.
> > Kernel code should always use =E2=80=9Cflexible array members=E2=80=9D[=
1] for these
> > cases. The older style of one-element or zero-length arrays should
> > no longer be used[2].
>=20
> These rules apply to the kernel, but uapi is not considered part of the
> kernel, so different rules apply.  Uapi header files should work with
> whatever compiler that can be used for compiling userspace.

Right, userspace isn't bound by these rules, but the kernel ends up
consuming these structures, so we need to fix them. The [0] -> []
changes (when they are not erroneously being used within other
structures) is valid for all compilers. Flexible arrays are C99; it's
been 23 years. :)

But, yes, where we DO break stuff we need to workaround it, etc.

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202206281104.7CC3935%40keescook.
