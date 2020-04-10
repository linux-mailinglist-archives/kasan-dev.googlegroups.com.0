Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBDVPYH2AKGQE5TV3EUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id F18161A459C
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 13:25:03 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id o27sf1823465qkj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 04:25:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586517903; cv=pass;
        d=google.com; s=arc-20160816;
        b=GMVJbQdYmaa9glid+S/cnc0rz+7VIbzackBZV/3zNBOKVEoIksDLWDt3/f06o6VnsW
         cKpi59tUT3SbY9mKqWlUFMUPWj3B8G2/jZJoU9DD4JtRxe/29rtWHHCvphP1+CQ9NWMN
         +kS+lWQSCn7yJi+1QIOu2OE8SSBT/U6br2+Eq4M5dD9IW9sC3c677hO/GfKxlyMqj0Lw
         EfPMDXcbHixNKN1ZqgY9johk5wYEezBv/jUGcHggC0d24MsmIWCEqLewE6vUy/O0bSWf
         K1VuS59Z4FKTm3XNRqR/SHGDo4Yw+j0RdzFAQN2A5/qSQ/461S6GfDbb4LA4Dvw2xtsX
         nNQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=7t65G7VaPhVbwmXF0d6ks0njfsbiZl4xbDDlkUZ2wHo=;
        b=Vm/JHeBNfsxf/GM8ku7MDPBclM2oFiNTHW35/sZ33ZUt0KR/9FExXFHElVYz21CBTx
         QERN/jTEwqYi9UVBin6uMOeFljQiGgod8vKnZapXXkT2ptdbC9CX9HXuW2ZMg/07nRfG
         S0qAUb1IesgZzeo909JK0FveAfgx2MxBJ4kYViiT66HrYK7YzraxQUyxWnukzLQthZJr
         IzOyYbr2M46PGtSB8K3K1eYaggNDkhOJgczvZB2YV7Z2GYVGJUXCoejJ/OXvPclD2SHi
         7HXrPcTTRpS8SzGpH53Sa0xZ+oY6n+aJxdFJF1QcWOaVuhY4H0dwvAH6Ee/nv2bLPkn1
         MNpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ROQfgV0c;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7t65G7VaPhVbwmXF0d6ks0njfsbiZl4xbDDlkUZ2wHo=;
        b=PkpiBeCWBppu2Yu+l4dTuwksC4Y/Cw7eANmSSHzNOqIcHnihHKHoES4jYrIgw2380b
         Yf51zt9OtKn1nVjjQNePnamR1O3If0j3Sa79j4po/s7JD3mF1LE2p039IDS6uzFI/xHw
         lawlDS3JUdIcORiPEPQLKL5Wi4ofa2A21YzOefVAnflO/CvOC1Df1oJAWCxLkfWQh1me
         89nsLyxlDmHOiN1K7qB1N3dLPHp/LjAPtjfRxBB5kWh/Pwvc4YKUcNL8cYOpGTQyXIsm
         mphZufbJHHMnaeLC/bWOvUyTTkrl+DUNCAeKAqashm7tictTmVcf/AhmJqz2xoVFDb4I
         YCVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7t65G7VaPhVbwmXF0d6ks0njfsbiZl4xbDDlkUZ2wHo=;
        b=RUUcRRfST27qGf8qOR/+Gr+F0nxvwKAoMlmS9dfBRI8kgio/SWfbYpCptwF1paVKnt
         J6/pX9+Vxli+c3auVJhCMHupAhVzqpBa8EK4SbV5gflYApPdUfWcVBDfeppICYaxv968
         7o+dycwpLelsUQab8bq5VzNUoQyGGxwL1oHb/Gh1l8R0s2o3F23CxrbWmtMTdyUAVkKI
         oRCrPU4iP2cc82v4cYHQ3fTGHIQKrBlTnoWNkxwQ7rjH4bzgzT4X+Oc9SGPXBggMetMC
         hM6PrYDsqQtuxic70nt5zKTji2a+m1Bt/t5wT4f7OHCp756b+HfuhrlBJSEf8mupqKO/
         HWbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaFrmRd0JNg7+M4JtCSUghH/T2VpeC0rxIRHhnDapSDql2/CrRp
	z4agNQaqW/D8ARoJuM7jFT4=
X-Google-Smtp-Source: APiQypKvAxYQKuyzEEhwvYtLFd93Mz1YOpfiUanaagJLP3WWwG+IQa8Uki4+ZS64qs6ZzYRU2HIkrw==
X-Received: by 2002:a05:620a:c18:: with SMTP id l24mr3227264qki.363.1586517902812;
        Fri, 10 Apr 2020 04:25:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6c44:: with SMTP id h65ls8447978qkc.11.gmail; Fri, 10
 Apr 2020 04:25:02 -0700 (PDT)
X-Received: by 2002:a37:93c1:: with SMTP id v184mr3454031qkd.47.1586517902488;
        Fri, 10 Apr 2020 04:25:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586517902; cv=none;
        d=google.com; s=arc-20160816;
        b=kjkhdHm3l9WQ0rbALtZXcME7PS/XR04C7nwXG4+0K1Pp8q12pVvUhhPPO9z5B15cgr
         2OCIDQtQI71Q6t2Pq1zvN8YBmJTlQsNxtsjDBxn2oPAlMnee0JCczcM/G/+znVC7pHHk
         cLC2h7vakxXbQJv9LSu/gYNtD/JT5K0S4vA9N0GySIsG2XnOg9/F8QEch4ODpYBAZY+x
         IC67IbP9jYYMen4n6bM5Lcam8Vc6tIVQbOLNAkFd/zDspElfAqmcpzeI+TqA8Suf5m81
         vs0/VIq8WsHssZ+8R4TnEbrVPyU9z0iOmr6z9uJHepavLgXZ9gATJ/LANIuWFhsIWodJ
         ncjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=EyRGokCM/wVUU/nXIGOSGIM3r9LXN2RB/WA9Dd31/fo=;
        b=KAYh2ILU3cDHqJbBnKdKKU+KwojX8JM3fiMJgckvmU+GafjIaLjgKvlmsmBT+exW6N
         vcy1JRepZKlNXtMXLf0DV7+6KchdE1heo9Rnts/vpXPrt5LnOBgc1MVWDH2OXhAj6b7X
         sXqyZ1l6Sn4lGS/GceSApOkJkaV8pBZGEMT+X0DzWDH6/Vav4y1a7ZTCDlBb9/6iK3QH
         Ex2frYdvXxDIgMxalSTeCS65+kBkBJIxqWbBG3If/CE07EbaQK/BJ0CkxNEz2dzTxhsR
         7npwbejw+UGwTEK6QsKCHLuaCc1g6QFWVmTQc3QvtYV2twkyVaUxD+R/+NpAfc2GcozC
         +ZwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ROQfgV0c;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id f16si98949qte.3.2020.04.10.04.25.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 04:25:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id p60so770753qva.5
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 04:25:02 -0700 (PDT)
X-Received: by 2002:ad4:4665:: with SMTP id z5mr4803594qvv.32.1586517902125;
        Fri, 10 Apr 2020 04:25:02 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id p9sm1349995qkg.34.2020.04.10.04.25.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 04:25:01 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: KCSAN + KVM = host reset
Date: Fri, 10 Apr 2020 07:25:00 -0400
Message-Id: <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw>
References: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
Cc: Paolo Bonzini <pbonzini@redhat.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, kvm@vger.kernel.org
In-Reply-To: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=ROQfgV0c;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f30 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 10, 2020, at 5:47 AM, Marco Elver <elver@google.com> wrote:
>=20
> That would contradict what you said about it working if KCSAN is
> "off". What kernel are you attempting to use in the VM?

Well, I said set KCSAN debugfs to =E2=80=9Coff=E2=80=9D did not help, i.e.,=
 it will reset the host running kvm.sh. It is the vanilla ubuntu 18.04 kern=
el in VM.

github.com/cailca/linux-mm/blob/master/kvm.sh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/AC8A5393-B817-4868-AA85-B3019A1086F9%40lca.pw.
