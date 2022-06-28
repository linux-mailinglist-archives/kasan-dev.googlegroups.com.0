Return-Path: <kasan-dev+bncBCUO3AHUWUIRB54X5WKQMGQE2KTM4PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id EF7A855ECD0
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 20:44:08 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id v2-20020a622f02000000b0052573fc72f8sf5378103pfv.11
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:44:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656441847; cv=pass;
        d=google.com; s=arc-20160816;
        b=aNwJakXuvbNrnfMXOy65vMpBPpKly4+7wQbaiQUusDVi3edfeFNm/qcw8Fe4EqLpB2
         0E2OwlrNwzsnqGJifk7yZYJZwyOq8oaKhK0SSImTTPcom+BnT5Yi/nSiSg0AZ0Cnq8nu
         WyzUlZEUJPIyeNZfbeyzhvdWRL/xd7L4KoTdIw2I3DImP0e13rZEBOpeRDwPydZpbZ6X
         LTwjDI5nObNAU96BfkG7mBc3gCZWOMv0ZTxmBZqUEQWePWbXPw2YlbNN2AZ80Dp2cT2+
         YdBZ0szgRI5oF3jeEQiepSBD/B9fXlNrI48B2PwTChmqQRw0ebNhDvDeC1EciqO21Y+f
         PrHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uvAxK0d3X5B514Xwr6mv8jUK/6cwSvRLNaLiaphJ76o=;
        b=OCTXK2FpDFriA560EJwp30h03E9dyebtQeqqVrqN9GEK8xx7BoQMuQfhUtssM1L0pW
         bDX5xthawg7wTOIGdjmpRt3vfwC5GvNd3voPe57WAMnHkyGB9n5EItJS8gbWCYuVq1+y
         2B+Kdn3CRZtTVDUoIRAWMQqG7iD+AEvCRQijee/B3HDI7Lx6GVTobxtIkwmixufSvmiN
         oIwgUzjcASgz3gUTT7fTzVEd7Faa84wScwgdZ2dlv2f8vtUTxV+StdTTwQ00+jIcLFg9
         aUDs4btwXMuA5a5SDwx1bV2jKYeTmOnnN8SmJtin6VFXbw5ts9dcJ//hcrv3884Dyw/X
         qNRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=QDfPPT0f;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=jgg@ziepe.ca
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uvAxK0d3X5B514Xwr6mv8jUK/6cwSvRLNaLiaphJ76o=;
        b=r8gIs6TtVAoQsHBdUjtiiSI4caAAQWVAjUhmak8cR5YeqfNKhWZR5RQcLGq6O4hkbD
         zu0AB4dtdUv+Ms8koHP9EXPD5ohyVugYpBe8XZrlcAczKFhDHFSjTeWVhbeKwcMDDtrE
         abXx45YbAoBmX8zuwsTdtMm/HsptgIi1miFkKx0MYzwuiWiCvOx92wGFao1D6B03Uzj8
         HsT2uqtGEz1nfTexsmSgwoGP38Ey95TvOS6B0T/J3g3wOgCVn17YTWeH+6boWG3mUE9a
         EP5OBWLY9Oh9BaJFI69uNtCLrQ4IHlBIlucIE/J2sTe0rzHpZOT2rjWqGxEOpXGcpMbR
         BTbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uvAxK0d3X5B514Xwr6mv8jUK/6cwSvRLNaLiaphJ76o=;
        b=MuzRPffNhIxshfIeMCB+WzUJSMClAMltlm83H9a6m/4gtWHquo+RILZLvhzE/bpltR
         MLosw5KFVPvhkRm90sLI/TmRhoZDrucf7nPnqsgLzq4/Ym3t3xMMinhMZV7NQwpGpJWw
         9O5JdHBEgkSE7CL4rSe2mGfbISWGdxIt3x9+GqAYate5bCSKQ3GH9EG8xrmCpVziO1m+
         2RUU4UoUTNvOE2QgWO8GOhW3TLyXCVsAu1AcM+N54oG4PLXpdA+CmfXKmE53e5RAKtXx
         /6GICVqLMyVsYZY/fHltEkjwUGMe/0HTlP49BvbA5vX7OAYFWIcfo4EmkJ1IiVSlpDwH
         /+Lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora87douRWvqa64Tcg5obOasv5NzUxwoRC0kWjJZIr1avsAxhEGNw
	+WsifpDERjAzcFivyRN2SOM=
X-Google-Smtp-Source: AGRyM1utkQUkpO9Yz+S9cFZsLk0yCNyxxSq+aJucQm5SqnBuLWoIAacSm/jwWFxRIenWzCwrhyWpCg==
X-Received: by 2002:a63:a70d:0:b0:40c:a1e3:23c2 with SMTP id d13-20020a63a70d000000b0040ca1e323c2mr18548786pgf.84.1656441847175;
        Tue, 28 Jun 2022 11:44:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b92:b0:1ea:cce6:4e6f with SMTP id
 lr18-20020a17090b4b9200b001eacce64e6fls179088pjb.0.-pod-control-gmail; Tue,
 28 Jun 2022 11:44:06 -0700 (PDT)
X-Received: by 2002:a17:90b:3143:b0:1ec:be03:e0a5 with SMTP id ip3-20020a17090b314300b001ecbe03e0a5mr1181739pjb.30.1656441846514;
        Tue, 28 Jun 2022 11:44:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656441846; cv=none;
        d=google.com; s=arc-20160816;
        b=W9WSBeoT6xqegul/k4wDF9z0y7UlA6IP/y559JO8vjT7XKY1CTC59VERahPH5CDZMy
         BzJSu5VMITCUdvdg/8LnlMpbyqZfI5Iplgi8pJdqijoLY8jvM3dPyQ9Jb7/fgH5SE/SB
         yAiVonq6bqoDbA7ajWSTXKYj0OwNIR1h3VcMcW7oibbYtYsIZzEsADyeGcOYGjtCdbuk
         C+mOYysGda9oazkKeC6vd/PMQkXXrs/TFDY18M3xL5aK3Iq0kq8URoXEYJdiWgPPQHy7
         XjmxaScGMXL9KPBA/SF6ExOJn8GSp7c4Ucgx8fnz7/CVREnUtBL2bVKzTeUfLXGomxJK
         0gJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=srd0vxfduo9pXREXizXvQ1Gwi/kEACFP1rdXcY0Aglg=;
        b=V9NoUFD0VaKBp8G2EpOuPvK+pxiklicY5i6Q64xHWqkXB/sxXgJXTfgQS2S/U0izRv
         pV//j1Bf/BeMrUxe5mx0v+0jVchR43VmIgChtfKOesQ3WispqR45SRdDLRUl6HWSYRkK
         LgUEE+n9sgo0r0g7nyCuQsA8OVcYlTgYdhPnPpfaaRAvTnEPy4y/plpYRZ+wsj6X9y8B
         w2h9guBpM/OIQ5A8iaiduD2FTq4G1w1Lngi8XF3STS9hz/e+yOMuBa976WWrnbmB/Wk/
         V+jTiuWHdVdDTlBDxk5WZ9nsAvBTmhMGhNzMPKWDfJIPzb+7BVG56wpOr3iSwI8vswIh
         VNvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=QDfPPT0f;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=jgg@ziepe.ca
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id o1-20020a056a00214100b005253d5b9000si538391pfk.2.2022.06.28.11.44.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 11:44:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id y14so21339129qvs.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 11:44:06 -0700 (PDT)
X-Received: by 2002:a05:622a:7:b0:31b:74bd:1597 with SMTP id x7-20020a05622a000700b0031b74bd1597mr6494688qtw.677.1656441846052;
        Tue, 28 Jun 2022 11:44:06 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-142-162-113-129.dhcp-dynamic.fibreop.ns.bellaliant.net. [142.162.113.129])
        by smtp.gmail.com with ESMTPSA id h9-20020ac85149000000b003050bd1f7c9sm9708477qtn.76.2022.06.28.11.44.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jun 2022 11:44:05 -0700 (PDT)
Received: from jgg by mlx with local (Exim 4.94)
	(envelope-from <jgg@ziepe.ca>)
	id 1o6GBw-0035y2-Fs; Tue, 28 Jun 2022 15:44:04 -0300
Date: Tue, 28 Jun 2022 15:44:04 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: Kees Cook <keescook@chromium.org>
Cc: Daniel Borkmann <daniel@iogearbox.net>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-kernel@vger.kernel.org, x86@kernel.org, dm-devel@redhat.com,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org, kvm@vger.kernel.org,
	intel-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
	netdev@vger.kernel.org, bpf@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-can@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org,
	lvs-devel@vger.kernel.org, linux-mtd@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-mmc@vger.kernel.org,
	nvdimm@lists.linux.dev, netfilter-devel@vger.kernel.org,
	coreteam@netfilter.org, linux-perf-users@vger.kernel.org,
	linux-raid@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	v9fs-developer@lists.sourceforge.net, linux-rdma@vger.kernel.org,
	alsa-devel@alsa-project.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
Message-ID: <20220628184404.GS23621@ziepe.ca>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
 <20220628004052.GM23621@ziepe.ca>
 <202206281009.4332AA33@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202206281009.4332AA33@keescook>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=QDfPPT0f;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f2e as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca
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

On Tue, Jun 28, 2022 at 10:54:58AM -0700, Kees Cook wrote:

 
> which must also be assuming it's a header. So probably better to just
> drop the driver_data field? I don't see anything using it (that I can
> find) besides as a sanity-check that the field exists and is at the end
> of the struct.

The field is guaranteeing alignment of the following structure. IIRC
there are a few cases that we don't have a u64 already to force this.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628184404.GS23621%40ziepe.ca.
