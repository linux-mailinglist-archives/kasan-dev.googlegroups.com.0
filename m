Return-Path: <kasan-dev+bncBCCMH5WKTMGRBG4DRCQAMGQEJB6YS3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 409846A9948
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:18:05 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 79-20020a630452000000b005030840e570sf785675pge.9
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:18:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677853083; cv=pass;
        d=google.com; s=arc-20160816;
        b=LpO3WxIvXzlC4HCAs4a/0aDbanvyc+IODfWfgXwZFLTCm9UJVFYNNGEWc5ZrsgDkzH
         w+H5A4/ew4XVATqSoG+fSieGm0MOxz5Uu6Aoyq9nLNBCtFIZO06cpmXsxZmVmFEtnG37
         k3F3jcxQFyv/28o1h88eaUF7+ryElEBcuqjkrLY+grbPz7KQWFsIB5n2E5EPio25WCcQ
         3g8lVXSR3KLRLXah2tepEeVujSEq+zZEW3mGxuDClLk4huvb7IZIMivsUvsVQkcVXU4p
         2AMEgNw199aUpk4fG166BkkQPm4U4/ugb9pcwL0ky3fApOUtOzh1eN+c09ZMDhbS4D64
         9FUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sjtl04od+C9UF4cpyIKVqIy6BTC/xrC9PvpfzatorKc=;
        b=VhIJ6oXgrmcuGIm/8Wy6sBTYtV25RmYj/OY9C2iz3qSEUXjCy6fTWPzcrpsOa69gIc
         VW7GGJANkbNt6vbkL3HHMe0OoO4GZUzpISJ31b55E6om5742nm0DxCmTKJndF0NScKiD
         XXY6EdvpQTr41P5evwubcXnTzX8ewhoOlQemlQ66x9C9yKr/yx5SLrS+qTBWCwc+YTyN
         EJAS5RNE0d0DPz3x4DeRH9z/465XXkeUTzqtq2XYt+KKU2dz0yT+la255NQJ1bdkp9wz
         usBfhBJJD8/WzfOWG+WuAKqVNdG3/RVn+ZLsvzJRIxMHNRHKtwy/jaZ2unmuklcXUyDc
         qzeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fjGTvIsV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677853083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sjtl04od+C9UF4cpyIKVqIy6BTC/xrC9PvpfzatorKc=;
        b=adisa4WtSX/OOnUuOmYnuOP6n9T5hPrGLjQGRBNOuDpNA5GLLULfVLzP+sGQb1hrty
         fd6d2AXciM63x8HQvcHQN1AGGShBoguqdKbuirOGD37MWXjJoK++bkei1jGcpL2JXo/e
         cQZFOmgCWILZAodoPF0nllw6riBVYDF7knVd/OElwDGxtLru+hVqoGUmfWeZN+67DQ/c
         iwsGgNgpkI/esWnFUSQrO+cINLYpEx5/sJll9NF26XNR8qQT8JZ+nyy/LtqffvJsvtF8
         aYLF0so4Y3BBnb4Zzs/iqTdDdPeg7rbSoRXoNLoqPMmCIqayPB6hNnD1pG4Q//bIaPjr
         FcQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677853083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=sjtl04od+C9UF4cpyIKVqIy6BTC/xrC9PvpfzatorKc=;
        b=f0I77q16L9WSpE7ABYaa92IIPnHPaqU46XsMLOdXyFVlLjgPYGCqTKcbIFxrfsf3Q3
         GynqqMzJYbuqjJwx825Pjui5DPImxe3DENswdkky8RgkeRG8At9mt26iBcPM/8Hf5IeT
         fv171DqlObLDfer0omdlGGuCl6PYkr/CLrGC0XZ1WUkmLRcz4PMEqUQDY8hevKU78OOI
         X6ftGJkQxcsIraCoPHgQ6etIN90YWw5nUT4DFzQsNkMQbWYx09fl6BOPDdtnSFSRG2/E
         TXp56o1/QmOx+vxgjNggp9P+PDAa4ZLEGlf/PiQHFuGC2xc+rrovKaVRl+iNVvst+7cw
         ecEQ==
X-Gm-Message-State: AO0yUKVed0HIkbZsMKdUIPW3lHmrymAhGVnZs63idPAJnRa/U646/o0V
	CPT4cPwNqZvvyiza+AquFWI=
X-Google-Smtp-Source: AK7set/LFMnAau97/sZfLCjleK8M+9yLCa0xIwxhO+OM8NGBLkxkrqxr1PEmrgvA3JLpYGkaB2P9MQ==
X-Received: by 2002:a17:90a:c257:b0:233:bada:17b5 with SMTP id d23-20020a17090ac25700b00233bada17b5mr662096pjx.4.1677853083541;
        Fri, 03 Mar 2023 06:18:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3890:b0:237:7ef0:5b8 with SMTP id
 mu16-20020a17090b389000b002377ef005b8ls6452234pjb.3.-pod-canary-gmail; Fri,
 03 Mar 2023 06:18:02 -0800 (PST)
X-Received: by 2002:a17:902:f689:b0:198:f8c9:7f4b with SMTP id l9-20020a170902f68900b00198f8c97f4bmr6022351plg.2.1677853082758;
        Fri, 03 Mar 2023 06:18:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677853082; cv=none;
        d=google.com; s=arc-20160816;
        b=cmKH+G9bwAmy3S62010pYrIFUWyET1WZg7hI/FtXNz5oWSUw82BLIGZs+i/wXj3gvw
         8r8SRI6MdTo7Hn0aTGLiVJgLVIDvIdoh7XureSpvHaofthdhUgGo6Hd2c4y2Ma1yioeF
         a7Q00hzm8uTC3erhJmh8M5AY0WSq1nWWWu0n3D0tCY0i4hEOR3c7skd/maP/Frw8eRcO
         T9Nzs9jEmFjgebCzcLvI/HWS7Z8oSMvo86cHtEIQpvnPTgIpZ/A4goaepM0QB1D9MneK
         R46ILmn6bHDFlJfXkkTwov0Hcc6ovu7VLRmeNTWuxlvk/tqV9/dlgXAXQbsk7PHU+xy6
         qiwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0B3hgicuXjM7bBAtA4QLzoXhHV0rOr+vQWIDTCOLWjA=;
        b=VoDRzoiSuzRBZbffbF+ZFddaWdOQLreonEKQpwx8qcUGxYEvnsRJQR3XIiwXnSwsw8
         wBO1vzl3xGZOHg62Nac1W0GvBX8OnqfgfnnGKhZ1ULjjMT1djS7IwecWsMbZte75Qev7
         7024r3rvMXKe6u2T8jg+ChJlck/9JydqPY8rv6UyZL3wbuow8+ND23xwuR3+2uPgU1dE
         ZD54cPhIB/NuWFLZUZBapmVBbRtnPBj83bAbmayClouOaS1nd2GiilTl3AqBG9KJDHKa
         TV+SgOz6NVZUH/eQuukCXUj9YmE+yR7qQ17VxFjNQ3wB/HDE3vfOyeajjsrjwcZBjUEi
         GLAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fjGTvIsV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id 18-20020a630212000000b00502efc8c657si94657pgc.4.2023.03.03.06.18.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:18:02 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id d12so1001120ioe.10
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:18:02 -0800 (PST)
X-Received: by 2002:a02:634e:0:b0:3ea:f622:3c7 with SMTP id
 j75-20020a02634e000000b003eaf62203c7mr633456jac.5.1677853082348; Fri, 03 Mar
 2023 06:18:02 -0800 (PST)
MIME-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com> <20230303141433.3422671-4-glider@google.com>
In-Reply-To: <20230303141433.3422671-4-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Mar 2023 15:17:25 +0100
Message-ID: <CAG_fn=XpUkTxQytHtWLCuU+w5nu2De0ri+rW3fupot3VRMu51g@mail.gmail.com>
Subject: Re: [PATCH 4/4] kmsan: add memsetXX tests
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fjGTvIsV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as
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

This is the second version of the patch. Sorry for the inconvenience.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXpUkTxQytHtWLCuU%2Bw5nu2De0ri%2BrW3fupot3VRMu51g%40mail.gmail.com.
