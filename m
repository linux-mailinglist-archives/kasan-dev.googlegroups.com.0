Return-Path: <kasan-dev+bncBDULZYNR2QMRBAEKV3WAKGQELUEGUMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33B45BE106
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 17:17:21 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id o9sf859875lfd.7
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 08:17:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569424640; cv=pass;
        d=google.com; s=arc-20160816;
        b=zqbfM54r0GkRKY9plgKzgEbl/8btZBpGXFyqXM9lPJuwQzqn6HREHd9wSs2lYZtg+2
         +lp+fiHIdwQhgKiLFzkqfaogNpZ4zatx4Pi9ZJKnlmPaib1O+N5a61sA9a62b8uoHIXX
         g3qxOlQ279cm90WuBw6ICxfCOQHVup0xncE6vWAiX88cJqQWtY9wlTbp7pRgRpiqVTb3
         /uEzsZxVYlF5LGzfYEF+rm9OwIPpjIs+UPO7GETOprZDn7dxgoz81eNwLKAdq9J8lMdb
         P4NS9D1PiQNyhWm0NsDpbVcYm/bFRLgJvbAQ8Ckn/zMzExBeUim5eC+dPu+qlplC1k/5
         Zh9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=KsgGmx67atj4s9HAgZyXPUwq5+mjxXAPc0ifsxoSvEY=;
        b=qX3xczHRABdKjqu6CXuBRtlBFaDtckJiMoFqVko/yUnWxsIuCotOq+8dO/mFtRuVdf
         GFbPkph/uSHgSIMOlxAmks7BHzjfkurEU51SONEcuuIAcGi3H8FEXvq/DGGQGilhBBF3
         6S304v7GoPEAyEZBOaA9j5m0H68hLrdjBwBzcTZXJf3PQuwv1cob0395VTzZMeWlDibq
         JJ4vH0P67Oe+GtV1OlSp752RPxrQbu88pebNkdU5pgJxMQm5Y/LE4Drx8huQQwxS98PF
         MIRs61MzmjDZmcCK2JwxQmwsloQL3edFpwmAwYov1ZwGuIvJ35TYjfhAdn+rneZEhZPY
         Dfnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eghD7xF1;
       spf=pass (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=festevam@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KsgGmx67atj4s9HAgZyXPUwq5+mjxXAPc0ifsxoSvEY=;
        b=Wfk0Di2CnqaQMA2YsAo+VHoqFxi2bKHDaWIKvD1sbuG0P81NKqeQhynkHeLrydmbfT
         MnDHZ9S1esJtPZN+gRqPO/Mf/Kc9CrFhhA3U0MtonEomgPx0qpU+v045YpnsLopWJtcw
         nJegjAtjPnrNFnrNa/+zOQdWd26rqjUjgetaBcx87h0pV6Rkfzb+1kBsKaaaAqhxDFak
         4M1Iukxv1FcquZnlMUKEvpB+9wv+DBCslUfTnOoFD6Yr4CjcTz+Q+8gtUy8VzKqYsvL/
         jw5kjmtbm0QY2+qnaE7Rxp72+kVttriOKWRsovv9y59FB2QzBWHpC4HoFexxq/+nqWsa
         60sA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KsgGmx67atj4s9HAgZyXPUwq5+mjxXAPc0ifsxoSvEY=;
        b=OSQydYwG1IVESg4zVbutIAZkD2ddaakzmew+hJf71XAP3Oyk1HuZpgaHH3gnW8DNEi
         Dn+B4YNYK26UT8+fiEQiY0ybuuzIZ3G7XBNXh+EFyn+WaWj0Xk73zfsRDSPinuOVyMBS
         Jw85Pup2+tcAMDYdJCkxKjwBDe8YMPWb9MAWG9gQrgTafz3E1MNu6cvqhz55WhWA/Y16
         eAm3ELMsNm4GxNGbwf/97bJCADlAONXc8Oabi9jLuDk5/k8qNXzO5lZUI5jaVDDqE+UL
         1iZaUOLKVaqK8ubKPC3vFupR6OGGkRbxMVIRPJodjj0OFV/7Kj6Wswchons3F2yBHda9
         CsAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KsgGmx67atj4s9HAgZyXPUwq5+mjxXAPc0ifsxoSvEY=;
        b=BAyiD7mNxShKB8BvVFUj0rNJMxd64jel/kyMxAnTy7I9hoiNox9H1g/sfi14gQsT9r
         YtUvFYArLubThOFoQ9YJC6h80fX0P+Ik1124zYXIve8P3rl3ZOdw1BUDzjqewp4N/AFG
         giNpQBUAmxvmVczngNwmQwNMyevOzE8Tm+3csy5t9nbpC+5Xg/blDFfWm8Xlom1NVbhV
         oy3B/S402htbTxnrVN9sr9wr+DlQufiz9E/DmJ82oh3qrI08zGp5/xyBl54RkdTPMXuq
         Bqfw66RAu8Sm/3oBptQ0019HyVdts2GcACQPeda/Gcq/eluxl51tuOczWvS2as8t72z1
         ZfTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWGHtOaQEaHwAPEOvNjX4vGPVboDB7C8KgUUV1DqqggHmVcrAym
	1ZLHJFHMwRROHXedM7htviw=
X-Google-Smtp-Source: APXvYqwQDMXuDZH5oWRSkWfgFTb46shufvU0AZSDXwyKM0F4LA1XoKx4IKZxlRIsdOGqy33lL5Yugw==
X-Received: by 2002:a2e:4704:: with SMTP id u4mr6789441lja.203.1569424640758;
        Wed, 25 Sep 2019 08:17:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3101:: with SMTP id x1ls952621ljx.1.gmail; Wed, 25 Sep
 2019 08:17:20 -0700 (PDT)
X-Received: by 2002:a2e:810e:: with SMTP id d14mr7045043ljg.160.1569424640192;
        Wed, 25 Sep 2019 08:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569424640; cv=none;
        d=google.com; s=arc-20160816;
        b=I5sYxa645MParLDRVB1tGWq34FwQ28FJWl6P3EAZ5X9vyv8i692PKDtZJjO2xuIWPR
         RB0QSlANRit7ar2pVMZTJ+KhXvSQWBDTFDo8L+mGG2gvnxXtdIxLolTZADY0Ip1s6Fy1
         mOX9F7V44qa7U99y9gCIeIxjMByVrRa+gTB6sWLZlE4aMMAtFsb7gTyOdrJUJlJ4UZk3
         3vElaiKhtT4HeajUre3WmdtMbQFGqG1fX4pnktHOIJn1P5lmMRF8izhmvraH85iQWoRZ
         fCNkvXd74gKShOn1xctDuwWPs87fA807myhqEwjy8HQAP4QmhaZ76ElGtsM1jd8R7Cz5
         ji4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rTBq6P5OxsGLjoGVhyAwZM8k0vklyHGTB2oJI82Er7M=;
        b=dNEUe4d9b7Myf690MRscx1oLu9dkmORG8ZKA8ISS9O47bzSqJl4MoHLhe7trkGchs5
         3h6hd1pTcOS0b1YV5k2S0ie5m0eWaYLUSzAyU4PARtOdws4c2tQ847AysYECSD+tXgtS
         cnf7P+71LhutZ53pHqkBCC5wb4muGOHvYcsNEKyUvAC6eV/91Ogz8EnQDXpPRAWGl33x
         0MDT80LKLgKXAf/BBqxpgH8JoiFoKDxVvnzfuYGAJ7gjvKkKFZSllrpOOb5vjuTpjwA2
         TVcQ99HGM4W5fvLwXh5UbpwPAhe8vuBzMrfCdEbu1Uinq0Im+0mPbMUBkf8q/iZ1XF3X
         H3tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eghD7xF1;
       spf=pass (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=festevam@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id c8si382257lfm.4.2019.09.25.08.17.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2019 08:17:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id y23so6069553lje.9
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2019 08:17:20 -0700 (PDT)
X-Received: by 2002:a2e:b0f4:: with SMTP id h20mr1893730ljl.10.1569424639817;
 Wed, 25 Sep 2019 08:17:19 -0700 (PDT)
MIME-Version: 1.0
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com>
 <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com> <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
In-Reply-To: <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
From: Fabio Estevam <festevam@gmail.com>
Date: Wed, 25 Sep 2019 12:17:28 -0300
Message-ID: <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
To: Adam Ford <aford173@gmail.com>
Cc: Mike Rapoport <rppt@linux.ibm.com>, Rich Felker <dalias@libc.org>, linux-ia64@vger.kernel.org, 
	Petr Mladek <pmladek@suse.com>, linux-sh@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Heiko Carstens <heiko.carstens@de.ibm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Max Filippov <jcmvbkbc@gmail.com>, 
	Guo Ren <guoren@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org, 
	Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org, linux-c6x-dev@linux-c6x.org, 
	Yoshinori Sato <ysato@users.sourceforge.jp>, Richard Weinberger <richard@nod.at>, x86@kernel.org, 
	Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Mark Salter <msalter@redhat.com>, 
	Dennis Zhou <dennis@kernel.org>, Matt Turner <mattst88@gmail.com>, 
	linux-snps-arc@lists.infradead.org, uclinux-h8-devel@lists.sourceforge.jp, 
	devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	linux-um@lists.infradead.org, 
	The etnaviv authors <etnaviv@lists.freedesktop.org>, linux-m68k@lists.linux-m68k.org, 
	Rob Herring <robh+dt@kernel.org>, Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org, 
	Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>, 
	arm-soc <linux-arm-kernel@lists.infradead.org>, Michal Simek <monstr@monstr.eu>, 
	Tony Luck <tony.luck@intel.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, USB list <linux-usb@vger.kernel.org>, 
	linux-mips@vger.kernel.org, Paul Burton <paul.burton@mips.com>, 
	Vineet Gupta <vgupta@synopsys.com>, linux-alpha@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, linuxppc-dev@lists.ozlabs.org, 
	"David S. Miller" <davem@davemloft.net>, openrisc@lists.librecores.org, 
	Chris Healy <cphealy@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: festevam@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=eghD7xF1;       spf=pass
 (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243
 as permitted sender) smtp.mailfrom=festevam@gmail.com;       dmarc=pass
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

On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:

> I tried cma=256M and noticed the cma dump at the beginning didn't
> change.  Do we need to setup a reserved-memory node like
> imx6ul-ccimx6ulsom.dtsi did?

I don't think so.

Were you able to identify what was the exact commit that caused such regression?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX%2BnR1mpQB8s8-w%40mail.gmail.com.
